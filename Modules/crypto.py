__author__ = "mihprog"

__license__ = "GPL"
__version__ = "2.0.0"

__email__ = "mih@mihprog.com"
__status__ = "Production"


import os
import threading
import logging
import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

from Modules.utils import PipeConn, PipeEmpty
from Modules.peer_storage import PeerConfigStorage



class InvalidToken(Exception):
    pass


class Symmetric():
    __slots__ = ("_signing_key", "_encryption_key")
    def __init__(self, key: bytes | str) -> None:
        if type(key) is str:
            try:
                key = base64.urlsafe_b64decode(key)
            except binascii.Error as exc:
                raise ValueError(
                    "Key must be 32 bytes."
                ) from exc
        if len(key) != 32:
            raise ValueError(
                "Key must be 32 url-safe base64-encoded."
            )

        self._signing_key = key[:16]
        self._encryption_key = key[16:]


    @classmethod
    def generate_key(cls) -> bytes:
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data: bytes) -> bytes:
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, iv)

    def _encrypt_from_parts(self, data: bytes, iv: bytes) -> bytes:

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key),
            modes.CBC(iv),
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
                iv
                + ciphertext
        )

        h = HMAC(self._signing_key, hashes.SHA256())
        h.update(basic_parts)
        hmac = h.finalize()
        return basic_parts + hmac

    def decrypt(self, token: bytes | str) -> bytes:
        return self._decrypt_data(token)


    def _verify_signature(self, data: bytes) -> None:
        h = HMAC(self._signing_key, hashes.SHA256())
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

    def _decrypt_data(self, data: bytes) -> bytes:

        self._verify_signature(data)

        iv = data[:16]
        ciphertext = data[16:-32]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv)
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return unpadded



class SymmetricCrypto:
    __slots__ = ("pipe_in", "pipe_out", "__peer_storage", "crypto_by_peer", "__is_run", "__encrypter_proc",
                 "__decrypter_proc")
    def __init__(self, peer_storage: PeerConfigStorage, pipe_in: PipeConn, pipe_out: PipeConn):
        self.pipe_in = pipe_in
        self.pipe_out = pipe_out
        self.__peer_storage = peer_storage

        self.crypto_by_peer = {}

        for peer_id in self.__peer_storage.get_peers_id():
            peer_crypto = self.__peer_storage.get_peer_crypto(peer_id)
            if peer_crypto is None:
                logging.warning(f"{self.__class__.__name__} | Peer {peer_id} Encryption disabled")
                continue
            self.__event_handler("add", peer_id, peer_crypto)
        self.__peer_storage.add_listener(self.__event_handler)

        self.__is_run = True
        self.__encrypter_proc = threading.Thread(target=self.__encrypter, daemon=True)
        self.__decrypter_proc = threading.Thread(target=self.__decrypter, daemon=True)

        self.__encrypter_proc.start()
        self.__decrypter_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")

    def __event_handler(self, action, peer_id, crypto):
        match action:
            case "add" | "update":
                try:
                    key = crypto.get("key")
                    self.crypto_by_peer[peer_id] = Symmetric(str(key))
                except ValueError as e:
                    logging.warning(f"{self.__class__.__name__} | Peer {peer_id} crypto.key load error: {e}, Encryption disabled")
                    return

                except KeyError:
                    logging.warning(f"{self.__class__.__name__} | Peer {peer_id} crypto.key not found, Encryption disabled")
                    return

            case "del":
                self.crypto_by_peer[peer_id] = None

    def __encrypter(self):
        logging.info(f"{self.__class__.__name__} | Thread encrypter - started")
        while self.__is_run:
            try:
                try:
                    packet, peer_id = self.pipe_in.recv(timeout=1)
                except PipeEmpty:
                    continue
                encryptor = self.crypto_by_peer.get(peer_id)
                if encryptor is None:
                    self.pipe_out.send((packet, peer_id))
                    continue
                try:
                    self.pipe_out.send((encryptor.encrypt(packet), peer_id))
                except InvalidToken:
                    logging.debug(f"{self.__class__.__name__} | packet to {peer_id} encrypt error")
            except Exception as e:
                logging.error(f"{self.__class__.__name__} | Runtime error: {e}")
        logging.info(f"{self.__class__.__name__} | Thread encrypter - stopped")

    def __decrypter(self):
        logging.info(f"{self.__class__.__name__} | Thread decrypter - started")
        while self.__is_run:
            try:
                try:
                    packet, peer_id = self.pipe_out.recv(timeout=1)
                except PipeEmpty:
                    continue
                decryptor = self.crypto_by_peer.get(self.__peer_storage.peer_id)
                if decryptor is None:
                    self.pipe_in.send((packet, peer_id))
                    continue
                try:
                    self.pipe_in.send((decryptor.decrypt(packet), peer_id))
                except InvalidToken:
                    logging.debug(f"{self.__class__.__name__} | packet from {peer_id} decrypt error")
            except Exception as e:
                logging.error(f"{self.__class__.__name__} | Runtime error: {e}")
        logging.info(f"{self.__class__.__name__} | Thread decrypter - stopped")

    def is_use_crypto(self, peer_id):
        if self.crypto_by_peer.get(peer_id) is not None:
            return True
        else:
            return False

    def stop(self, wait=False):
        self.__is_run = False
        if wait:
            self.__encrypter_proc.join()
            self.__decrypter_proc.join()
        logging.info(f"{self.__class__.__name__} | Full - stopped")
