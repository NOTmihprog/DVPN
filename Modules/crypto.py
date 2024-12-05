__author__ = "mihprog"

__license__ = "GPL"
__version__ = "1.1.4"

__email__ = "mih@mihprog.com"
__status__ = "Development"


import threading
import logging

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from Modules.utils import PipeConn, PipeEmpty


class SymmetricCrypto:
    def __init__(self, peer_id, pipe_in: PipeConn, pipe_out: PipeConn):
        self.pipe_in = pipe_in
        self.pipe_out = pipe_out

        self.backend = default_backend()
        self.crypto_by_peer = {}
        self.block_size = 128
        self.peer_id = peer_id

        self.__is_run = True
        self.__encrypter_proc = threading.Thread(target=self.__encrypter)
        self.__decrypter_proc = threading.Thread(target=self.__decrypter)

        self.__encrypter_proc.start()
        self.__decrypter_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")

    def add_peer(self, peer_id: str, key: str) -> bool:
        """
        :param peer_id: str, len = 32, hex
        :param key: <crypto key>, base64, len = 32
        :return: ok: True, error: False
        """
        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            logging.warning(f"{self.__class__.__name__} | peer {peer_id} key not loaded len != 32")
            return False
        try:
            self.crypto_by_peer[peer_id] = Cipher(algorithms.AES(key), modes.ECB(), self.backend)
            return True
        except ValueError:
            logging.warning(f"{self.__class__.__name__} | Peer {peer_id} key not loaded")
            return False

    def del_peer(self, peer_id: str) -> bool:
        """
        :param peer_id: str, len = 32, hex
        :return: ok: True, error: False
        """
        if peer_id is None or self.crypto_by_peer.get(peer_id) is None:
            return False
        self.crypto_by_peer[peer_id] = None

    def update_peer(self, peer_id: str, key: str) -> bool:
        """
        :param peer_id: str, len = 32, hex
        :param key: <crypto key>, base64, len = 32
        :return: ok: True, error: False
        """
        return self.add_peer(peer_id=peer_id, key=key)

    def __encrypter(self):
        logging.info(f"{self.__class__.__name__} | Thread encrypter - started")
        while self.__is_run:
            try:
                packet, peer_id = self.pipe_in.recv(timeout=1)
            except PipeEmpty:
                continue
            encryptor = self.crypto_by_peer.get(self.peer_id)
            if encryptor is None:
                self.pipe_out.send((packet, peer_id))
                continue
            encryptor = encryptor.encryptor()
            padder = padding.PKCS7(self.block_size).padder()
            try:
                padded_packet = padder.update(packet) + padder.finalize()
                self.pipe_out.send((encryptor.update(padded_packet) + encryptor.finalize(), peer_id))
            except ValueError:
                logging.debug(f"{self.__class__.__name__} | packet to {peer_id} encrypt error")
        logging.info(f"{self.__class__.__name__} | Thread encrypter - stopped")

    def __decrypter(self):
        logging.info(f"{self.__class__.__name__} | Thread decrypter - started")
        while self.__is_run:
            try:
                packet, peer_id = self.pipe_out.recv(timeout=1)
            except PipeEmpty:
                continue
            decryptor = self.crypto_by_peer.get(self.peer_id)
            if decryptor is None:
                self.pipe_in.send((packet, peer_id))
                continue
            decryptor = decryptor.decryptor()
            unpadder = padding.PKCS7(self.block_size).unpadder()
            try:
                decrypted_packet = decryptor.update(packet)
                self.pipe_in.send((unpadder.update(decrypted_packet) + unpadder.finalize(), peer_id))
            except ValueError:
                logging.debug(f"{self.__class__.__name__} | packet from {peer_id} decrypt error")
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
