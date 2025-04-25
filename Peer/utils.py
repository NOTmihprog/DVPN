__author__ = "mihprog"

__license__ = "GPL"
__version__ = "2.0.0"

__email__ = "mih@mihprog.com"
__status__ = "Production"

import os
import random
import threading
import time
from typing import Optional, Union
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

import logging
import msgpack
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey

from Modules.crypto import Symmetric, InvalidToken
from Modules.peer_storage import PeerConfigStorage
from Modules.utils import EventPipe, PipeConn, PipeEmpty



@dataclass(slots=True)
class ServerStatus:
    addr: tuple[str, int]
    last_response: int

    def __bool__(self) -> bool:
        return False
    def __str__(self) -> str:
        return "Unknown"

    def __repr__(self) -> str:
        return f"Server {self.addr[0]}:{self.addr[1]} status {self.__str__()}"


class ServerConnected(ServerStatus):
    def __bool__(self) -> bool:
        return True
    def __str__(self) -> str:
        return "Connected"

class ServerDisconnected(ServerStatus):
    def __bool__(self) -> bool:
        return False
    def __str__(self) -> str:
        return "Disconnected"


class Client:
    def __init__(self,
                 pipe: PipeConn,
                 peer_storage: PeerConfigStorage,
                 event_pipe: EventPipe,
                 key: Union[bytes, str],
                 addr: tuple[str, int]
                 ):
        self.__pipe = pipe
        self.__peer_storage = peer_storage
        self.__public_key = Ed448PublicKey.from_public_bytes(key)
        self.__event_pipe = event_pipe
        self.__addr = addr
        self.__iv = None
        self.__private_key = None
        self.__session_key = None

        self.announce_interval = 15  # Seconds
        self.search_interval = 45  # Seconds

        self.last_announce = 0
        self.last_search = 0
        self.last_response = 0

        self.__log_prefix = f"{self.__class__.__name__} {self.__addr[0]}:{self.__addr[1]} | "

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver, daemon=True)
        self.__sender_proc = threading.Thread(target=self.__sender, daemon=True)

        self.__receiver_proc.start()
        self.__sender_proc.start()
        logging.info(self.__log_prefix + f"Connection status initiated")

    def get_server_status(self) -> ServerStatus:
        if self.__session_key is not None:
            return ServerConnected(addr=self.__addr, last_response=self.last_response)
        else:
            return ServerDisconnected(addr=self.__addr, last_response=self.last_response)

    def get_public_key(self):
        return self.__public_key.public_bytes_raw()

    def __create_event(self, status: ServerStatus):
        self.__event_pipe.event(server=self.__addr, status=bool(status))

    def __init_session(self):
        self.__iv = os.urandom(random.randint(14, 50))
        self.__private_key = X448PrivateKey.generate()
        self.__send_no_encrypt(self.__private_key.public_key().public_bytes_raw() + self.__iv, self.__addr)

    def __reg_session(self, packet):
        if len(packet) < 75:
            return
        peer_public_key = X448PublicKey.from_public_bytes(packet[:56])
        try:
            self.__public_key.verify(packet[56:56+114], packet[:56])
        except InvalidSignature:
            logging.info(self.__log_prefix + f"Reg session Invalid Signature")
            return
        shared_key = self.__private_key.exchange(peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=self.__iv,
        ).derive(shared_key)
        self.__session_key = Symmetric(derived_key)
        logging.info(self.__log_prefix + f"Connection status connected")
        self.__create_event(ServerConnected(addr=self.__addr, last_response=self.last_response))
        self.last_response = time.time()


    def __send_no_encrypt(self, packet: bytes, addr: tuple[str, int]):
        self.__pipe.send((packet, addr))

    def __recv(self) -> tuple[Optional[bytes], Optional[tuple[str, int]]]:
        try:
            return self.__pipe.recv(timeout=1)
        except PipeEmpty:
            return None, None

    def __send(self, packet: dict[str, any]):
        if self.__session_key is None:
            return
        self.__send_no_encrypt(self.__session_key.encrypt(msgpack.dumps(packet)), self.__addr)

    def __send_close(self):
        self.__send({"type": "close"})

    def send_announce(self):
        packet = {"type": "anno",
                  "peer_id": self.__peer_storage.peer_id}
        logging.debug(self.__log_prefix + f"Send announce")
        self.__send(packet)

    def send_search(self, peer_id):
        packet = {"type": "sear",
                  "peer_id": peer_id}
        logging.debug(self.__log_prefix + f"Send search peer {peer_id}")
        self.__send(packet)

    def send_search_all(self):
        for peer_id in self.__peer_storage.get_peers_id():
            if self.__peer_storage.peer_is_self(peer_id):
                continue
            elif self.__peer_storage.get_peer_endpoint(peer_id) is not None:
                continue
            self.send_search(peer_id)
            time.sleep(0.1)


    def __sender(self):
        while self.__is_run:
            if self.__session_key is not None:
                if self.last_response > 0 and time.time() - self.last_response >= self.announce_interval * 3:
                    logging.info(self.__log_prefix + f"Connection status disconnected")
                    self.__create_event(ServerDisconnected(addr=self.__addr, last_response=self.last_response))
                    self.drop_session()
                    continue

                if time.time() - self.last_announce >= self.announce_interval:
                    self.send_announce()
                    self.last_announce = time.time()
                elif time.time() - self.last_search >= self.search_interval:
                    self.send_search_all()
                    self.last_search = time.time()
                else:
                    time.sleep(1)
            else:
                self.__init_session()
                logging.debug(self.__log_prefix + f"Connection status connecting")
                time.sleep(1)

    def __decrypt(self, packet: bytes) -> Optional[bytes]:
        try:
            return self.__session_key.decrypt(packet)
        except InvalidToken:
            return None

    def drop_session(self):
        self.__send_close()
        self.__session_key = None
        self.last_response = 0

    def __receiver(self):
        while self.__is_run:
            packet, addr = self.__recv()
            if packet is None:
                continue
            if self.__session_key is None:
                self.__reg_session(packet)
                continue

            packet = self.__decrypt(packet)
            if packet is None:
                logging.info(self.__log_prefix + f"Received packet | Invalid Data")
                self.drop_session()
                continue
            try:
                packet = msgpack.loads(packet)
            except msgpack.ExtraData:
                logging.info(self.__log_prefix + f"Received packet | msgpack ExtraData")
                continue
            except msgpack.FormatError:
                logging.info(self.__log_prefix + f"Received packet | msgpack FormatError")
                continue
            except msgpack.StackError:
                logging.info(self.__log_prefix + f"Received packet | msgpack StackError")
                continue
            except ValueError:
                logging.info(self.__log_prefix + f"Received packet | msgpack ValueError")
                continue

            if type(packet) is not dict:
                logging.info(self.__log_prefix + f"Received packet | data type not dict")
                self.drop_session()
                continue
            packet_type = packet.get("type")
            match packet_type:
                case "resp":
                    self.last_response = time.time()
                    peer_id = packet.get("peer_id")
                    peer_addr = packet.get("addr")
                    if type(peer_id) is not str:
                        logging.info(self.__log_prefix + f"Received packet | addr not str")
                        continue

                    if type(peer_addr) is not list:
                        logging.info(self.__log_prefix + f"Received packet | addr not list")
                        continue

                    if len(peer_addr) < 2:
                        logging.info(self.__log_prefix + f"Received packet | addr len != 2")
                        continue

                    if type(peer_addr[0]) is not str:
                        logging.info(self.__log_prefix + f"Received packet | addr[0] not str")
                        continue

                    if type(peer_addr[1]) is not int:
                        logging.info(self.__log_prefix + f"Received packet | addr[1] not int")
                        continue

                    peer_addr = (peer_addr[0], peer_addr[1])

                    if not self.__peer_storage.peer_exists(peer_id):
                        logging.info(self.__log_prefix + f"Received packet | Peer {peer_id} not found in peer_storage")
                        continue

                    if self.__peer_storage.get_peer_endpoint(peer_id) == peer_addr:
                        logging.debug(self.__log_prefix + f"Peer {peer_id} receive endpoint {peer_addr[0]}:{peer_addr[1]}")
                        continue

                    if self.__peer_storage.peer_is_self(peer_id):
                        logging.info(self.__log_prefix + f"New self endpoint {peer_addr[0]}:{peer_addr[1]}")
                    else:
                        logging.info(self.__log_prefix + f"Peer {peer_id} new endpoint {peer_addr[0]}:{peer_addr[1]}")

                    self.__peer_storage.set_peer(peer_id, endpoint=peer_addr)
                    continue

                case "close":
                    logging.info(self.__log_prefix + f"Connection closed from server")
                    self.drop_session()
                    continue
                case _:
                    logging.info(self.__log_prefix + f"Received packet | Packet type {packet_type} not exist")
                    continue

    def stop(self, wait=False):
        self.__is_run = False
        if wait:
            self.__receiver_proc.join()
            self.__sender_proc.join()


class PingUtils:
    def __init__(self, peer_storage: PeerConfigStorage, pipe: PipeConn, event_pipe: EventPipe):
        self.__pipe = pipe
        self.__peer_storage = peer_storage
        self.__event_pipe = event_pipe

        self.ping_interval = 15 # Seconds

        self.__peer_ping = {}
        self.__peer_ping_send_time = {}
        self.__peer_ping_receive_time = {}
        self.__peer_ping_packets_send = {}

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver, daemon=True)
        self.__sender_proc = threading.Thread(target=self.__sender, daemon=True)

        self.__receiver_proc.start()
        self.__sender_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")

    def send_ping(self, peer_id: str):
        packet = b"ping" + random.randbytes(random.randint(65, 150))
        self.__pipe.send((packet, peer_id))

    def send_pong(self, peer_id: str):
        packet = b"pong" + random.randbytes(random.randint(65, 150))
        self.__pipe.send((packet, peer_id))

    def __create_event(self, peer_id: str, ping: int):
        self.__event_pipe.event(peer_id=peer_id, ping=ping)


    def __sender(self):
        logging.info(f"{self.__class__.__name__} | Thread sender - started")
        while self.__is_run:
            try:
                for peer_id in self.__peer_storage.get_peers_id():
                    if self.__peer_storage.peer_is_self(peer_id):
                        continue
                    if self.__peer_storage.get_peer_endpoint(peer_id) is None:
                        continue

                    ping_packets = self.__peer_ping_packets_send.get(peer_id)
                    if ping_packets is None:
                        ping_packets = 0

                    last_recv_time = self.__peer_ping_receive_time.get(peer_id)
                    if last_recv_time is None:
                        last_recv_time = 0

                    if ping_packets > 3 and (time.time_ns() - last_recv_time) / 1000000000 > self.ping_interval*3:
                        self.__peer_storage.del_peer_endpoint(peer_id)
                        continue

                    self.send_ping(peer_id)
                    self.__peer_ping_send_time[peer_id] = time.time_ns()
                    self.__peer_ping_packets_send[peer_id] = ping_packets + 1

                    logging.debug(f"{self.__class__.__name__} | send ping to peer {peer_id}")
                time.sleep(15)
            except Exception as e:
                logging.error(f"{self.__class__.__name__} | Runtime error: {e}")
        logging.info(f"{self.__class__.__name__} | Thread sender - stopped")

    def __receiver(self):
        logging.info(f"{self.__class__.__name__} | Thread receiver - started")
        while self.__is_run:
            try:
                try:
                    packet, peer_id = self.__pipe.recv(timeout=1)
                except PipeEmpty:
                    continue
                if packet[:4] == b"ping":
                    self.send_pong(peer_id)
                    logging.debug(f"{self.__class__.__name__} | receive ping from {peer_id}")
                elif packet[:4] == b"pong":
                    send_time = self.__peer_ping_send_time.get(peer_id)
                    if send_time is None:
                        continue
                    receive_time = time.time_ns()
                    ping = (receive_time - send_time)/1000000
                    self.__peer_ping[peer_id] = ping
                    self.__peer_ping_receive_time[peer_id] = receive_time
                    self.__create_event(peer_id, ping)
                    logging.debug(f"{self.__class__.__name__} |"
                                  f" receive pong from {peer_id}"
                                  f" ping: {ping}")
                else:
                    logging.info(f"{self.__class__.__name__} | packet from {peer_id} type {packet[:4]} not exist")
                    continue
            except Exception as e:
                logging.error(f"{self.__class__.__name__} | Runtime error: {e}")

        logging.info(f"{self.__class__.__name__} | Thread receiver - stopped")

    def det_ping(self, peer_id: str) -> int:
        ping = self.__peer_ping.get(peer_id)
        if ping is None:
            return 0
        return ping

    def stop(self, wait=False):
        self.__is_run = False
        if wait:
            self.__receiver_proc.join()
            self.__sender_proc.join()
        logging.info(f"{self.__class__.__name__} | Full - stopped")