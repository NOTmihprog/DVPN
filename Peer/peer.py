__author__ = "mihprog"

__license__ = "GPL"
__version__ = "2.0.0"

__email__ = "mih@mihprog.com"
__status__ = "Development"

from queue import Queue
from Modules.utils import PipeConn, PipeEmpty, EventPipe
from Peer.utils import Client
from Modules.peer_storage import PeerConfigStorage
import threading
import logging
import random
import socket
import time

class Peer:
    def __init__(self,
                    peer_storage: PeerConfigStorage,
                    servers: list[tuple[tuple[str, int], bytes]],
                    pipe: PipeConn,
                    event_pipe: EventPipe,
                    local_addr: str=None,
                    local_ports: tuple[int, int]=None
                 ):
        self.__pipe: PipeConn = pipe
        self.__event_pipe: EventPipe = event_pipe
        self.__peer_storage: PeerConfigStorage = peer_storage

        self.local_ports_range: tuple[int, int] = local_ports
        self.local_addr: str = local_addr

        self.__DADDR2ID: dict[tuple[str, int], str] = {}
        self.__ID2DADDR: dict[str, tuple[str, int]] = {}

        self.__clients: dict[tuple[str, int], Client] = {}
        self.__clients_pipe: dict[tuple[str, int], PipeConn] = {}

        self.__sock = None
        self.reinit_socket((local_addr, random.randint(self.local_ports_range[0], self.local_ports_range[1])))

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver, daemon=True)
        self.__sender_proc = threading.Thread(target=self.__sender, daemon=True)

        for peer_id in self.__peer_storage.get_peers_id():
            peer_endpoint = self.__peer_storage.get_peer_endpoint(peer_id)
            if peer_endpoint is None:
                continue
            self.__event_handler("add", peer_id, peer_endpoint)
        self.__peer_storage.add_listener(self.__event_handler)

        self.__event_pipe.add_listener(self.__status_handler)

        for server in servers:
            self.__add_client(addr=server[0], key=server[1])

        self.__receiver_proc.start()
        self.__sender_proc.start()
        logging.debug(f"{self.__class__.__name__} | Full - started")

    def __add_client(self, addr: tuple[str, int], key: bytes):
        client_pipe = PipeConn(Queue(), Queue())
        client = Client(
            pipe=PipeConn(input=client_pipe.output, output=self.__pipe.input),
            peer_storage=self.__peer_storage,
            event_pipe=self.__event_pipe,
            key=key,
            addr=addr
        )
        self.__clients[addr] = client
        self.__clients_pipe[addr] = client_pipe

    def __event_handler(self, action, peer_id, endpoint):
        match action:
            case "add" | "update":
                self.__add_endpoint(peer_id, endpoint)
            case "del":
                self.__del_endpoint(peer_id)

    def __add_endpoint(self, peer_id: str, endpoint: tuple[str, int]):
        last_addr = self.__ID2DADDR.get(peer_id)
        if last_addr is not None:
            del self.__DADDR2ID[last_addr]

        self.__DADDR2ID[endpoint] = peer_id
        self.__ID2DADDR[peer_id] = endpoint

    def __del_endpoint(self, peer_id: str):
        last_addr = self.__ID2DADDR.get(peer_id)
        if last_addr is not None:
            del self.__DADDR2ID[last_addr]

        del self.__ID2DADDR[peer_id]


    def reinit_socket(self, addr: tuple[str, int]):
        try:
            self.__sock.close()
        except AttributeError:
            pass

        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__sock.bind(addr)
        self.__sock.settimeout(1)

    def change_port(self):
        new_port = random.randint(self.local_ports_range[0], self.local_ports_range[1])
        try:
            self.reinit_socket((self.local_addr, new_port))
            logging.warning(f"{self.__class__.__name__} | Port changed new port {new_port}")
        except OSError as e:
            logging.warning(f"{self.__class__.__name__} | Change port to {new_port} error: {e}")
            time.sleep(0.1)
            self.change_port()

    def __status_handler(self, event: dict[str, any]):
        if event.get("server") is None:
            return
        if self.local_ports_range[0] == self.local_ports_range[1]:
            return
        offline = True
        for client_addr in self.__clients:
            if self.__clients.get(client_addr).get_server_status():
                offline = False
        if offline:
            self.change_port()

    def __receiver(self):
        logging.debug(f"{self.__class__.__name__} | Thread receiver - started")
        while self.__is_run:
            try:
                try:
                    packet, addr = self.__sock.recvfrom(65507)
                except TimeoutError:
                    continue
                except OSError as e:
                    logging.info(f"{self.__class__.__name__} | Thread receiver - socket OSError: {e}")
                    continue

                peer_id = self.__DADDR2ID.get(addr)
                if peer_id is None:
                    client_pipe = self.__clients_pipe.get(addr)
                    if client_pipe is not None:
                        client_pipe.send((packet, addr))
                    continue

                self.__pipe.send((packet, peer_id))
            except Exception as e:
                logging.error(f"{self.__class__.__name__} | Runtime error: {e}")
        logging.debug(f"{self.__class__.__name__} | Thread receiver - stopped")

    def __sender(self):
        logging.debug(f"{self.__class__.__name__} | Thread sender - started")
        while self.__is_run:
            try:
                try:
                    packet, peer_id = self.__pipe.recv(timeout=1)
                except PipeEmpty:
                    continue

                if type(peer_id) is tuple:
                    daddr = peer_id
                else:
                    daddr = self.__ID2DADDR.get(peer_id)
                    if daddr is None:
                        logging.debug(f"{self.__class__.__name__} | "
                                      f"packet to {peer_id}"
                                      f" destination addr not found")
                        continue
                if len(packet) <= 65507:
                    try:
                        self.__sock.sendto(packet, daddr)
                    except OSError as e:
                        logging.debug(f"{self.__class__.__name__} | packet to peer "
                                      f"{peer_id} socket OS Error: {e}")
                        continue
                else:
                    logging.debug(f"{self.__class__.__name__} | packet to peer"
                                  f" {peer_id} very long, len > 65507")
                    continue
            except Exception as e:
                logging.error(f"{self.__class__.__name__} | Runtime error: {e}")
        logging.debug(f"{self.__class__.__name__} | Thread sender - stopped")

    def get_local_addr(self):
        return self.__sock.getsockname()

    def get_client(self, addr: tuple[str, int]):
        return self.__clients.get(addr)

    def stop(self, wait=False):
        self.__is_run = False

        if wait:
            self.__receiver_proc.join()
            self.__sender_proc.join()
        self.__sock.close()
        logging.debug(f"{self.__class__.__name__} | Full - stopped")

