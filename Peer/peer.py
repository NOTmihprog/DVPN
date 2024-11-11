__author__ = "mihprog"

__license__ = "GPL"
__version__ = "1.1.4"

__email__ = "mih@mihprog.com"
__status__ = "Production"

from queue import Queue, Empty
import threading
import logging
import random
import socket
import time
import json


class RouteSearch:
    def __init__(self, serv_addr, serv_port, peer_id, sock, input=None):
        if input is None:
            self.input = Queue()
        else:
            self.input = input
        self.server_addr = serv_addr
        self.server_port = int(serv_port)
        self.peer_id = peer_id
        self.sock = sock

        self.DADDR2ID = {}
        self.ID2DADDR = {}
        self.peer_list = []
        self.peer_receive_time = {}

        self.serv_last_recv_time = None

        self.__is_run = True

        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__send_search_proc = threading.Thread(target=self.__send_search)
        self.__send_annonce_proc = threading.Thread(target=self.__send_annonce)

        self.__receiver_proc.start()
        self.__send_search_proc.start()
        self.__send_annonce_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")

    def update_socket(self, sock):
        self.sock = sock

    def __send_search(self):
        logging.info(f"{self.__class__.__name__} | Thread send search - started")
        while self.__is_run:
            for peer_id in self.peer_list:
                if peer_id == self.peer_id:
                    continue

                last_packet = self.peer_receive_time.get(peer_id)
                if last_packet is not None and (time.time_ns() - last_packet) / 1000000000 > 45:
                    self.__del_daddr(peer_id)

                packet = json.dumps({"type": "get", "id": peer_id}).encode("utf-8")
                try:
                    self.sock.sendto(packet, (self.server_addr, self.server_port))
                except OSError:
                    logging.debug(f"{self.__class__.__name__} | Send search error, OSError")
                time.sleep(0.1)
            time.sleep(30)
        logging.info(f"{self.__class__.__name__} | Thread send search - stopped")

    def __send_annonce(self):
        logging.info(f"{self.__class__.__name__} | Thread send annonce - started")
        while self.__is_run:
            packet = json.dumps({"type": "annonce", "id": self.peer_id}).encode("utf-8")
            try:
                self.sock.sendto(packet, (self.server_addr, self.server_port))
            except OSError:
                logging.debug(f"{self.__class__.__name__} | Send annonce error, OSError")
            time.sleep(10)
        logging.info(f"{self.__class__.__name__} | Thread send annonce - stopped")

    def __receiver(self):
        logging.info(f"{self.__class__.__name__} | Thread receiver - started")
        while self.__is_run:
            try:
                packet = self.input.get(timeout=1)
            except Empty:
                continue
            try:
                packet = packet.decode("utf-8")
            except UnicodeError:
                logging.debug(f"{self.__class__.__name__} | "
                              f"Packet from {self.server_addr}:{self.server_port} str decode error")
                continue

            try:
                data = json.loads(packet)
            except ValueError:
                logging.debug(f"{self.__class__.__name__} | "
                              f"Packet from {self.server_addr}:{self.server_port} json decode error")
                continue
            receive_time = time.time_ns()
            self.serv_last_recv_time = receive_time

            id = data.get("id")
            addr = data.get("addr")
            port = data.get("port")
            if id is None or addr is None or port is None:
                logging.debug(f"{self.__class__.__name__} |"
                              f" Packet from {self.server_addr}:{self.server_port} id or adrr or port is None")
                continue
            try:
                port = int(port)
            except ValueError:
                logging.debug(f"{self.__class__.__name__} |"
                              f" Packet from {self.server_addr}:{self.server_port} port not int")
                continue

            if id not in self.peer_list:
                logging.debug(f"{self.__class__.__name__} |"
                              f" Packet from {self.server_addr}:{self.server_port} peer id not in peer list")
                continue

            self.peer_receive_time[id] = receive_time
            last_addr = self.ID2DADDR.get(id)
            if last_addr is not None:
                del self.DADDR2ID[last_addr]

            self.DADDR2ID[(addr, port)] = id
            self.ID2DADDR[id] = (addr, port)
        logging.info(f"{self.__class__.__name__} | Thread receiver - stopped")

    def __del_daddr(self, peer_id):
        last_addr = self.ID2DADDR.get(peer_id)
        if last_addr is not None:
            del self.DADDR2ID[last_addr]

        self.ID2DADDR[peer_id] = None

    def add_peer(self, peer) -> bool:
        """
        :param peer: {"id": "<peer_id>"}
        :return: ok: True, error: False
        """
        peer_id = peer.get("id")
        if peer_id is not None and peer_id != self.peer_id:
            self.peer_list.append(peer.get("id"))
            return True
        else:
            return False

    def del_peer(self, peer) -> bool:
        """
        :param peer: {"id": "<peer_id>"}
        :return: ok: True, not found: False
        """
        peer_id = peer.get("id")
        if peer_id is not None and peer_id in self.peer_list:
            self.peer_list.remove(peer_id)
            self.__del_daddr(peer_id)
            return True
        else:
            return False

    def stop(self):
        self.__is_run = False
        self.__receiver_proc.join()
        self.__send_search_proc.join()
        self.__send_annonce_proc.join()
        logging.info(f"{self.__class__.__name__} | Full - stopped")


class PingUtils:
    def __init__(self, peer_id, input=None, output=None):
        if input is None:
            self.input = Queue()
        else:
            self.input = input
        if output is None:
            self.output = Queue()
        else:
            self.output = output

        self.peer_id = peer_id
        self.peer_list = []

        self.peer_send_time = {}
        self.peer_receive_time = {}
        self.peer_ping = {}

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__sender_proc = threading.Thread(target=self.__sender)

        self.__receiver_proc.start()
        self.__sender_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")

    def __sender(self):
        logging.info(f"{self.__class__.__name__} | Thread sender - started")
        while self.__is_run:
            for peer_id in self.peer_list:
                buf = f"ping{peer_id}".encode("utf-8")
                self.peer_send_time[peer_id] = time.time_ns()
                self.output.put((buf, peer_id))
            time.sleep(15)
        logging.info(f"{self.__class__.__name__} | Thread sender - stopped")

    def __receiver(self):
        logging.info(f"{self.__class__.__name__} | Thread receiver - started")
        while self.__is_run:
            try:
                ping_type, peer_id = self.input.get(timeout=1)
            except Empty:
                continue
            if ping_type == "ping":
                buf = f"pong{peer_id}".encode("utf-8")
                self.output.put((buf, peer_id))
            elif ping_type == "pong":
                send_time = self.peer_send_time.get(peer_id)
                if send_time is None:
                    continue
                receive_time = time.time_ns()
                ping = (receive_time - send_time)/1000000
                self.peer_ping[peer_id] = ping
                self.peer_receive_time[peer_id] = receive_time
        logging.info(f"{self.__class__.__name__} | Thread receiver - stopped")

    def add_peer(self, peer) -> bool:
        """
        :param peer: {"id": "<peer_id>"}
        :return: ok: True, error: False
        """
        peer_id = peer.get("id")
        if peer_id is not None and peer_id != self.peer_id:
            self.peer_list.append(peer_id)
            return True
        else:
            return False

    def del_peer(self, peer) -> bool:
        """
        :param peer: {"id": "<peer_id>"}
        :return: ok: True, not found: False
        """
        peer_id = peer.get("id")
        if peer_id is not None and peer_id in self.peer_list:
            self.peer_list.remove(peer_id)
        else:
            return False

    def stop(self):
        self.__is_run = False
        self.__receiver_proc.join()
        self.__sender_proc.join()
        logging.info(f"{self.__class__.__name__} | Full - stopped")


class Peer:
    def __init__(self, peer_id, serv_addr, serv_port, local_addr=None, local_ports=None, input=None, output=None):
        if input is None:
            self.input = Queue()
        else:
            self.input = input

        if output is None:
            self.output = Queue()
        else:
            self.output = output

        self.peer_id = str(peer_id)
        self.server_addr = str(serv_addr)
        self.server_port = int(serv_port)
        self.local_ports_range = local_ports
        self.local_addr = local_addr

        self.sock = None
        self.reload_socket(local_addr, random.randint(self.local_ports_range[0], self.local_ports_range[1]))

        self.__routeSearch = RouteSearch(serv_addr, serv_port, peer_id, self.sock)
        self.__ping_utils = PingUtils(peer_id, output=self.input)

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__sender_proc = threading.Thread(target=self.__sender)
        self.__port_control_proc = threading.Thread(target=self.__port_control)

        self.__receiver_proc.start()
        self.__sender_proc.start()
        self.__port_control_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")

    def reload_socket(self, local_addr=None, local_port=None):
        try:
            self.sock.close()
        except AttributeError:
            pass

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if local_addr is not None and local_port is not None:
            self.sock.bind((local_addr, local_port))
        self.sock.settimeout(1)

        try:
            self.__routeSearch.update_socket(self.sock)
        except AttributeError:
            pass

    def __port_control(self):
        logging.info(f"{self.__class__.__name__} | Thread port_control - started")
        while self.__is_run:
            time.sleep(40)
            server_status = self.is_serv_online()
            if server_status is None:
                continue
            elif server_status:
                continue
            self.reload_socket(self.local_addr, random.randint(self.local_ports_range[0], self.local_ports_range[1]))
            logging.warning(f"{self.__class__.__name__} | Thread port_control - port changed")

        logging.info(f"{self.__class__.__name__} | Thread port_control - stopped")

    def __receiver(self):
        logging.info(f"{self.__class__.__name__} | Thread receiver - started")
        while self.__is_run:
            try:
                packet, addr = self.sock.recvfrom(65507)
            except TimeoutError:
                continue
            except OSError:
                continue
            if addr[0] == self.server_addr and addr[1] == self.server_port:
                self.__routeSearch.input.put(packet)
                continue

            peer_id = self.__routeSearch.DADDR2ID.get(addr)
            if peer_id is None:
                continue

            if packet[:4] == b"ping" or packet[:4] == b"pong":
                if packet[4:] == self.peer_id.encode("utf-8"):
                    self.__ping_utils.input.put((packet[:4].decode("utf-8"), peer_id))
                    continue
            self.output.put((packet, peer_id))
        logging.info(f"{self.__class__.__name__} | Thread receiver - stopped")

    def __sender(self):
        logging.info(f"{self.__class__.__name__} | Thread sender - started")
        while self.__is_run:
            try:
                packet, peer_id = self.input.get(timeout=1)
            except Empty:
                continue

            daddr = self.__routeSearch.ID2DADDR.get(peer_id)
            if daddr is None:
                logging.debug(f"{self.__class__.__name__} | "
                              f"packet to {peer_id} destination addr not found")
                continue
            if len(packet) <= 65507:
                self.sock.sendto(packet, daddr)
            else:
                logging.debug(f"{self.__class__.__name__} | "
                              f"packet to peer {peer_id} very long, len > 65507")
                continue
        logging.info(f"{self.__class__.__name__} | Thread sender - stopped")

    def add_peer(self, peer) -> bool:
        """
        :param peer: {"id": "<peer_id>"}
        :return: ok: True, is self: False
        """
        result = True
        result = result and self.__routeSearch.add_peer(peer)
        result = result and self.__ping_utils.add_peer(peer)
        return result

    def del_peer(self, peer) -> bool:
        """
        :param peer: {"id": "<peer_id>"}
        :return: ok: True, not found: False
        """
        result = True
        result = result and self.__routeSearch.del_peer(peer)
        result = result and self.__ping_utils.del_peer(peer)
        return result

    def stop(self):
        self.__is_run = False

        self.__routeSearch.stop()
        self.__ping_utils.stop()

        self.__receiver_proc.join()
        self.__sender_proc.join()
        self.__port_control_proc.join()
        self.sock.close()
        logging.info(f"{self.__class__.__name__} | Full - stopped")

    def get_ping(self, peer_id: str) -> int:
        ping = self.__ping_utils.peer_ping.get(peer_id)
        return ping if ping is not None else 0

    def is_peer_online(self, peer_id: str) -> bool or None:
        if peer_id == self.peer_id:
            return True
        last_pong = self.__ping_utils.peer_receive_time.get(peer_id)
        if last_pong is None:
            return None
        if (time.time_ns()-last_pong)/1000000000 > 45:
            return False
        else:
            return True

    def is_serv_online(self) -> bool or None:
        slrt = self.__routeSearch.serv_last_recv_time
        if slrt is None:
            return None
        if (time.time_ns()-slrt)/1000000000 > 45:
            return False
        else:
            return True

    def get_peer_endpoint(self, peer_id) -> tuple or None:
        return self.__routeSearch.ID2DADDR.get(peer_id)
