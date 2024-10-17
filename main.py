import json
import os
import random
import socket
import sys
import time
from tuntap import TunTap
from ipaddress import IPv4Address
import signal
from queue import Queue, Empty
import threading
from tabulate import tabulate

SERVER_ADDR = "62.109.29.213"
SERVER_PORT = 6484

PEER_ID = "f33674b7e7034a55b0e849e95b3c66a6"

LOCAL_ADDR = "0.0.0.0"
LOCAL_PORT = random.randint(8647, 9942)

TUN_NAME = "dnet"

net_config_file = open("./netconfig.json")
net_config = json.load(net_config_file)
net_config_file.close()

PEER_ADDR = list(filter(lambda peer: peer.get("id") == PEER_ID, net_config.get("peers")))[0].get("addr")


class TUNControl:
    def __init__(self, tun_name, addr, mask, peers, input: Queue = None, output: Queue = None):
        if input is None:
            self.input = Queue()
        else:
            self.input = input

        if output is None:
            self.output = Queue()
        else:
            self.output = output

        self.ID2LADDR = {}
        self.LADDR2ID = {}
        self.update_peers(peers)

        self.tun = TunTap(nic_type="Tun", nic_name=tun_name)
        self.tun.config(addr, mask)
        self.addr = str(addr)

        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__sender_proc = threading.Thread(target=self.__sender)

        self.__is_run = True

        self.__receiver_proc.start()
        self.__sender_proc.start()

    def update_peers(self, peers):
        for peer in peers:
            id = peer.get("id")
            addr = peer.get("addr")

            self.ID2LADDR[id] = addr
            self.LADDR2ID[addr] = id

    def __receiver(self):
        while self.__is_run:
            try:
                buf = self.tun.read()
            except OSError:
                break
            if (buf[0] >> 4) == 4:
                saddr = str(IPv4Address(buf[12:16]))
                daddr = str(IPv4Address(buf[16:20]))
            else:
                continue

            if saddr != self.addr:
                continue
            peer_id = self.LADDR2ID.get(daddr)
            if peer_id is None:
                print(f"packet to {daddr} peer id not fount")
                continue
            self.output.put((buf, peer_id))

    def __sender(self):
        while self.__is_run:
            try:
                buf, peer_id = self.input.get(timeout=1)
            except Empty:
                continue
            try:
                self.tun.write(buf)
            except OSError:
                print("write error")

    def stop(self):
        self.__is_run = False
        self.__receiver_proc.join()
        self.tun.close()
        self.__sender_proc.join()


class RouteSearch:
    def __init__(self, serv_addr, serv_port, peer_id, peers, sock, input=None):
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
        self.update_peers(peers)

        self.is_run = True

        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__send_search_proc = threading.Thread(target=self.__send_search)
        self.__send_annonce_proc = threading.Thread(target=self.__send_annonce)

        self.__receiver_proc.start()
        self.__send_search_proc.start()
        self.__send_annonce_proc.start()

    def update_peers(self, peers):
        self.peer_list = list(peer.get("id") for peer in peers)

    def __send_search(self):
        while self.is_run:
            for peer_id in self.peer_list:
                if peer_id == self.peer_id:
                    continue
                packet = json.dumps({"type": "get", "id": peer_id}).encode("utf-8")
                self.sock.sendto(packet, (self.server_addr, self.server_port))
                time.sleep(0.1)
            time.sleep(30)

    def __send_annonce(self):
        while self.is_run:
            packet = json.dumps({"type": "annonce", "id": self.peer_id}).encode("utf-8")
            self.sock.sendto(packet, (self.server_addr, self.server_port))
            time.sleep(10)

    def __receiver(self):
        while self.is_run:
            packet = self.input.get()
            try:
                packet = packet.decode("utf-8")
            except UnicodeError:
                print(f"Packet from {self.server_addr}:{self.server_port} str decode error")
                continue

            try:
                data = json.loads(packet)
            except ValueError:
                print(f"Packet from {self.server_addr}:{self.server_port} json decode error")
                continue

            id = data.get("id")
            addr = data.get("addr")
            port = data.get("port")
            if id is None or addr is None or port is None:
                print(f"Packet from {self.server_addr}:{self.server_port} id or adrr or port is None")
                continue
            try:
                port = int(port)
            except ValueError:
                print(f"Packet from {self.server_addr}:{self.server_port} port not int")
                continue

            if id not in self.peer_list:
                print(f"Packet from {self.server_addr}:{self.server_port} peer id not in peer list")
                continue

            last_addr = self.ID2DADDR.get(id)
            if last_addr is not None:
                del self.DADDR2ID[last_addr]

            self.DADDR2ID[(addr, port)] = id
            self.ID2DADDR[id] = (addr, port)


class PingUtils:
    def __init__(self, peer_id, peers, input=None, output=None):
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
        self.update_peers(peers)

        self.peer_send_time = {}
        self.peer_receive_time = {}
        self.peer_ping = {}

        self.is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__sender_proc = threading.Thread(target=self.__sender)

        self.__receiver_proc.start()
        self.__sender_proc.start()

    def update_peers(self, peers):
        self.peer_list = list(filter(lambda peer_id: peer_id != self.peer_id, list(peer.get("id") for peer in peers)))

    def __sender(self):
        while self.is_run:
            for peer_id in self.peer_list:
                buf = f"ping{peer_id}".encode("utf-8")
                self.peer_send_time[peer_id] = time.time_ns()
                self.output.put((buf, peer_id))
            time.sleep(15)

    def __receiver(self):
        while self.is_run:
            ping_type, peer_id = self.input.get()
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


class Peer:
    def __init__(self, peer_id, peers, serv_addr, serv_port, local_addr=None, local_port=None, input=None, output=None):
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

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if local_addr is not None and local_port is not None:
            self.sock.bind((local_addr, local_port))

        self.routeSearch = RouteSearch(serv_addr, serv_port, peer_id, peers, self.sock)
        self.ping_utils = PingUtils(peer_id, peers, output=self.input)

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__sender_proc = threading.Thread(target=self.__sender)

        self.__receiver_proc.start()
        self.__sender_proc.start()

    def update_peers(self, peers):
        self.routeSearch.update_peers(peers)
        self.ping_utils.update_peers(peers)

    def __receiver(self):
        while self.__is_run:
            packet, addr = self.sock.recvfrom(10240)
            if addr[0] == self.server_addr and addr[1] == self.server_port:
                self.routeSearch.input.put(packet)
                continue

            peer_id = self.routeSearch.DADDR2ID.get(addr)
            if peer_id is None:
                continue

            if packet[:4] == b"ping" or packet[:4] == b"pong":
                if packet[4:] == self.peer_id.encode("utf-8"):
                    self.ping_utils.input.put((packet[:4].decode("utf-8"), peer_id))
                    continue
            self.output.put((packet, peer_id))

    def __sender(self):
        while self.__is_run:
            packet, peer_id = self.input.get()

            daddr = self.routeSearch.ID2DADDR.get(peer_id)
            if daddr is None:
                print(f"packet to {peer_id} destination addr not fount")
                continue
            self.sock.sendto(packet, daddr)

    def get_ping(self, peer_id):
        ping = self.ping_utils.peer_ping.get(peer_id)
        return ping if ping is not None else 0

    def is_online(self, peer_id):
        if peer_id == self.peer_id:
            return True
        last_pong = self.ping_utils.peer_receive_time.get(peer_id)
        if last_pong is None:
            return None
        if (time.time_ns()-last_pong)/1000000000 > 45:
            return False
        else:
            return True


peer = Peer(PEER_ID, net_config.get("peers"), SERVER_ADDR, SERVER_PORT, LOCAL_ADDR, LOCAL_PORT)

tun_control = TUNControl(tun_name=TUN_NAME, addr=PEER_ADDR, mask=net_config.get("mask"),
                         input=peer.output, output=peer.input, peers=net_config.get("peers"))


def clear():
    # for windows
    if os.name == 'nt':
        _ = os.system('cls')
    # for mac and linux(here, os.name is 'posix')
    else:
        _ = os.system('clear')


def signal_handler(sig, frame):
    print('pressed Ctrl+C, exiting.')
    tun_control.stop()
    time.sleep(1)
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

table_headers = ["Peer ID", "Local", "Endpoint", "Status", "Ping"]

while True:
    clear()
    table_data = []
    for peer_data in net_config.get("peers"):
        peer_id = peer_data.get("id")
        endpoint = peer.routeSearch.ID2DADDR.get(peer_id)
        if endpoint is not None:
            endpoint = f"{endpoint[0]}:{endpoint[1]}"

        peer_online = peer.is_online(peer_id)
        ping = peer.get_ping(peer_id)
        if peer_id == PEER_ID:
            peer_status = "Self"
            ping = "~"
        elif peer_online:
            peer_status = "Online"
        else:
            peer_status = "Offline"


        table_data.append([
            peer_id, peer_data.get("addr"), endpoint,
            peer_status, ping])

    print(tabulate(table_data, headers=table_headers))
    time.sleep(5)


