__author__ = "mihprog"

__license__ = "GPL"
__version__ = "2.0.0"

__email__ = "mih@mihprog.com"
__status__ = "Development"


from typing import Optional, Union
import socket
import threading
import time

import logging
import msgpack

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


from Modules.crypto import Symmetric, InvalidToken


class Server:
    def __init__(self, sock: socket.socket, key: Union[str, bytes], peer_id_len: int=32):
        self.__sock = sock
        self.__peer_id_max_len = peer_id_len
        self.__private_key = Ed448PrivateKey.from_private_bytes(key)

        self.__peer_session: dict[tuple[str, int], Symmetric] = {} # addr: key
        self.__ADDR2PEER_ID: dict[tuple[str, int], str] = {}
        self.__PEER_ID2ADDR: dict[str, tuple[str, int]] = {}
        self.__last_announce: dict[tuple[str, int], Optional[float]] = {}
        self.__peer_search_peers: dict[str, list[str]] = {}
        self.timeout = 45 # Seconds

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver, daemon=True)
        self.__garbage_collector_proc = threading.Thread(target=self.__garbage_collector, daemon=True)

        self.__receiver_proc.start()
        self.__garbage_collector_proc.start()


    def __send_no_encrypt(self, packet: bytes, addr: tuple[str, int]):
        try:
            self.__sock.sendto(packet, addr)
        except PermissionError:
            logging.info(f"{self.__class__.__name__} | send to {addr[0]}:{addr[1]} PermissionError")
            return None
        except OSError:
            logging.info(f"{self.__class__.__name__} | send to {addr[0]}:{addr[1]} OSError")
            return None

    def __send(self, packet: dict[str, any], addr: tuple[str, int]):
        session_key = self.__peer_session.get(addr)
        if session_key is None:
            return
        self.__send_no_encrypt(session_key.encrypt(msgpack.dumps(packet)), addr)

    def __recv(self) -> tuple[Optional[bytes], Optional[tuple[str, int]]]:
        try:
            return self.__sock.recvfrom(65507)
        except BlockingIOError:
            logging.info(f"{self.__class__.__name__} | BlockingIOError")
            return None, None
        except TimeoutError:
            return None, None
        except OSError:
            logging.info(f"{self.__class__.__name__} | OSError")
            return None, None

    def __reg_peer_session(self, packet, addr):
        if len(packet) < 75:
            logging.info(f"{self.__class__.__name__} | Packet from {addr[0]}:{addr[1]} len < 75")
            return
        try:
            private_key = X448PrivateKey.generate()
            peer_public_key = X448PublicKey.from_public_bytes(packet[:56])
            shared_key = private_key.exchange(peer_public_key)

            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=packet[56:106],
            ).derive(shared_key)
        except ValueError:
            logging.info(f"{self.__class__.__name__} | reg session Value Error from {addr[0]}:{addr[1]}")
            return
        self.__peer_session[addr] = Symmetric(derived_key)
        self.__last_announce[addr] = None
        logging.info(f"{self.__class__.__name__} | New session from {addr[0]}:{addr[1]}")

        public_key = private_key.public_key().public_bytes_raw()
        self.__send_no_encrypt(public_key + self.__private_key.sign(public_key), addr)

    def __send_close(self, addr: tuple[str, int]):
        self.__send({"type": "close"}, addr)

    def drop_session(self, addr: tuple[str, int], send_close=True):
        if send_close:
            self.__send_close(addr)
        del self.__peer_session[addr]
        peer_id = self.__ADDR2PEER_ID.get(addr)
        if peer_id is not None:
            self.del_peer_id(peer_id)
        try:
            del self.__last_announce[addr]
        except KeyError:
            pass
        logging.info(f"{self.__class__.__name__} | {addr[0]}:{addr[1]} Session dropped")

    @staticmethod
    def __decrypt(packet: bytes, session: Symmetric) -> Optional[bytes]:
        try:
            return session.decrypt(packet)
        except InvalidToken:
            return None

    def __send_response(self, sendto: tuple[str, int], addr: tuple[str, int], peer_id: str):
        self.__send({"type": "resp", "peer_id": peer_id, "addr": addr}, sendto)


    def __announce(self, addr: tuple[str, int], peer_id: str):
        self.__last_announce[addr] = time.time()

        last_peer_id = self.__ADDR2PEER_ID.get(addr)
        if last_peer_id is not None and last_peer_id != peer_id:
            self.drop_session(addr)
            return

        last_addr = self.__PEER_ID2ADDR.get(peer_id)
        if last_addr == addr:
            self.__send_response(addr, addr, peer_id)
            logging.debug(f"{self.__class__.__name__} | Session {addr[0]}:{addr[1]} recv announce")
            return

        if last_addr is not None and last_addr != addr:
            self.drop_session(last_addr)
            last_addr = None

        if last_addr is None:
            self.add_peer_id(addr, peer_id)
            self.__send_response(addr, addr, peer_id)
            logging.info(f"{self.__class__.__name__} | Session {addr[0]}:{addr[1]} peer_id: {peer_id}")
            return

    
    def __search(self, self_peer: str, peer_id: str):
        self_searched_peers = self.__peer_search_peers.get(self_peer)
        if self_searched_peers is None:
            self.__peer_search_peers[self_peer] = []
            self_searched_peers = []
        if not peer_id in self_searched_peers:
            logging.info(f"{self.__class__.__name__} | peer_id: {self_peer} new search {peer_id}")
            self.__peer_search_peers[self_peer].append(peer_id)

        searched_peers = self.__peer_search_peers.get(peer_id)
        if searched_peers is None:
            return

        if self_peer in searched_peers:
            logging.info(f"{self.__class__.__name__} | peer_id: {self_peer} search {peer_id}")
            addr = self.__PEER_ID2ADDR.get(self_peer)
            if addr is None:
                logging.warning(f"{self.__class__.__name__} | peer_id: {self_peer} search {peer_id} addr is none")
                return
            search_addr = self.__PEER_ID2ADDR.get(peer_id)
            if search_addr is None:
                logging.warning(f"{self.__class__.__name__} | peer_id: {self_peer} search {peer_id}"
                                f" search_addr is none")
                return
            self.__send_response(addr, search_addr, peer_id)
            return


    def add_peer_id(self, addr: tuple[str, int], peer_id: str):
        self.__ADDR2PEER_ID[addr] = peer_id
        self.__PEER_ID2ADDR[peer_id] = addr

    def del_peer_id(self, peer_id: str):
        addr = self.__PEER_ID2ADDR.get(peer_id)
        if addr is not None:
            del self.__ADDR2PEER_ID[addr]

        try:
            del self.__peer_search_peers[peer_id]
        except KeyError:
            logging.debug(f"{self.__class__.__name__} | peer_id: {peer_id} del search_peers KeyError")
            pass

        del self.__PEER_ID2ADDR[peer_id]

    def __garbage_collector(self):
        while self.__is_run:
            try:
                for addr in self.__last_announce.copy():
                    last_announce = self.__last_announce[addr]
                    if last_announce is None or time.time() - last_announce > self.timeout:
                        self.drop_session(addr)
                time.sleep(self.timeout/3)
            except Exception as e:
                logging.error(f"{self.__class__.__name__} | Runtime error {type(e).__name__}: {e}")


    def __receiver(self):
        while self.__is_run:
            try:
                packet, addr = self.__recv()
                if packet is None:
                    continue

                session = self.__peer_session.get(addr)
                if session is None:
                    self.__reg_peer_session(packet, addr)
                    continue

                packet = self.__decrypt(packet, session)
                if packet is None:
                    logging.info(f"{self.__class__.__name__} | Packet from {addr[0]}:{addr[1]} Invalid Data")
                    continue

                try:
                    packet = msgpack.loads(packet)
                except msgpack.ExtraData:
                    logging.info(f"{self.__class__.__name__} | Packet from {addr[0]}:{addr[1]} msgpack ExtraData")
                    continue
                except msgpack.FormatError:
                    logging.info(f"{self.__class__.__name__} | Packet from {addr[0]}:{addr[1]} msgpack FormatError")
                    continue
                except msgpack.StackError:
                    logging.info(f"{self.__class__.__name__} | Packet from {addr[0]}:{addr[1]} msgpack StackError")
                    continue
                except ValueError:
                    logging.info(f"{self.__class__.__name__} | Packet from {addr[0]}:{addr[1]} msgpack ValueError")
                    continue


                if type(packet) is not dict:
                    logging.info(f"{self.__class__.__name__} | Packet from {addr[0]}:{addr[1]} packet type not dict")
                    self.drop_session(addr)
                    continue
                match packet.get("type"):
                    case "anno":
                        peer_id = packet.get("peer_id")
                        if peer_id is None:
                            logging.info(f"{self.__class__.__name__} | Packet from {addr[0]}:{addr[1]} peer_id is none")
                            continue
                        
                        elif type(peer_id) is not str:
                            logging.info(f"{self.__class__.__name__} | Packet from {addr[0]}:{addr[1]} peer_id not str")
                            continue
                        
                        elif len(peer_id) > self.__peer_id_max_len:
                            logging.info(f"{self.__class__.__name__} | Packet from {addr[0]}:{addr[1]}"
                                         f" len peer_id {len(peer_id)} > {self.__peer_id_max_len}")
                            continue
                        
                        self.__announce(addr, peer_id)
                        continue

                    case "sear":
                        self_peer_id = self.__ADDR2PEER_ID.get(addr)
                        if self_peer_id is None:
                            continue
                        peer_id = packet.get("peer_id")
                        if type(peer_id) is not str:
                            continue
                        elif len(peer_id) > self.__peer_id_max_len:
                            continue
                        
                        self.__search(self_peer_id, peer_id)
                        continue

                    case "close":
                        self.drop_session(addr, send_close=False)
                        logging.info(
                            f"{self.__class__.__name__} | connection close from {addr[0]}:{addr[1]}")
                        continue

                    case _:
                        logging.info(f"{self.__class__.__name__} | Packet from {addr[0]}:{addr[1]}"
                                     f" type {packet.get('type')} not found")
                        continue

            except Exception as e:
                logging.error(f"{self.__class__.__name__} | Runtime error {type(e).__name__}: {e}")