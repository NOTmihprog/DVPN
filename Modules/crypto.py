__author__ = "mihprog"
__copyright__ = "Copyright 2024, Planet Earth"
__credits__ = ["mihprog", "coffe"]

__license__ = "GPL"
__version__ = "1.1.4"

__maintainer__ = "mihprog"
__email__ = "mih@mihprog.com"
__status__ = "Development"

from queue import Queue, Empty
import threading
import logging

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class SymmetricCrypto:
    def __init__(self, peers, peer_id, dec_in=None, dec_out=None, enc_in=None, enc_out=None):
        if dec_in is None:
            self.dec_in = Queue()
        else:
            self.dec_in = dec_in

        if dec_out is None:
            self.dec_out = Queue()
        else:
            self.dec_out = dec_out

        if enc_in is None:
            self.enc_in = Queue()
        else:
            self.enc_in = enc_in

        if enc_out is None:
            self.enc_out = Queue()
        else:
            self.enc_out = enc_out

        self.backend = default_backend()
        self.crypto_by_peer = {}
        self.block_size = 128
        self.update_peers(peers)
        self.peer_id = peer_id

        self.__is_run = True
        self.__encrypter_proc = threading.Thread(target=self.__encrypter)
        self.__decrypter_proc = threading.Thread(target=self.__decrypter)

        self.__encrypter_proc.start()
        self.__decrypter_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")

    def update_peers(self, peers):
        for peer in peers:
            key = peer.get("key")
            peer_id = peer.get("id")
            if key is None:
                logging.debug(f"{self.__class__.__name__} | Peer {peer_id} key not found")
                continue
            key = base64.urlsafe_b64decode(key)
            if len(key) != 32:
                logging.warning(f"{self.__class__.__name__} | peer {peer_id} key not loaded len != 32")
                continue
            try:
                self.crypto_by_peer[peer_id] = Cipher(algorithms.AES(key), modes.ECB(), self.backend)

            except ValueError:
                logging.warning(f"{self.__class__.__name__} | Peer {peer_id} key not loaded")

    def __encrypter(self):
        logging.info(f"{self.__class__.__name__} | Thread encrypter - started")
        while self.__is_run:
            try:
                packet, peer_id = self.enc_in.get(timeout=1)
            except Empty:
                continue
            encryptor = self.crypto_by_peer.get(peer_id)
            if encryptor is None:
                self.enc_out.put((packet, peer_id))
                continue
            encryptor = encryptor.encryptor()
            padder = padding.PKCS7(self.block_size).padder()
            try:
                padded_packet = padder.update(packet) + padder.finalize()
                self.enc_out.put((encryptor.update(padded_packet) + encryptor.finalize(), peer_id))
            except ValueError:
                logging.debug(f"{self.__class__.__name__} | packet to {peer_id} encrypt error")
        logging.info(f"{self.__class__.__name__} | Thread encrypter - stopped")

    def __decrypter(self):
        logging.info(f"{self.__class__.__name__} | Thread decrypter - started")
        while self.__is_run:
            try:
                packet, peer_id = self.dec_in.get(timeout=1)
            except Empty:
                continue
            decryptor = self.crypto_by_peer.get(self.peer_id)
            if decryptor is None:
                self.dec_out.put((packet, peer_id))
                continue
            decryptor = decryptor.decryptor()
            unpadder = padding.PKCS7(self.block_size).unpadder()
            try:
                decrypted_packet = decryptor.update(packet)
                self.dec_out.put((unpadder.update(decrypted_packet) + unpadder.finalize(), peer_id))
            except ValueError:
                logging.debug(f"{self.__class__.__name__} | packet from {peer_id} decrypt error")
        logging.info(f"{self.__class__.__name__} | Thread decrypter - stopped")

    def is_use_crypto(self, peer_id):
        if self.crypto_by_peer.get(peer_id) is not None:
            return True
        else:
            return False

    def stop(self):
        self.__is_run = False
        self.__encrypter_proc.join()
        self.__decrypter_proc.join()
        logging.info(f"{self.__class__.__name__} | Full - stopped")
