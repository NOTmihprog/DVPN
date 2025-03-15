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

SERVER_ADDR = "127.0.0.1"
SERVER_PORT = 6484

PEER_ID = "2fce1fc531804ae090cedbf4595fdf1f"

LOCAL_ADDR = "127.0.0.1"
LOCAL_PORT = random.randint(8647, 9942)

TUN_NAME = "dnet"

net_config_file = open("./netconfig.json")
net_config = json.load(net_config_file)
net_config_file.close()

PEER_ADDR = list(filter(lambda peer: peer.get("id") == PEER_ID, net_config.get("peers")))[0].get("addr")


class TUNControl:
    def __init__(self, tun_name, addr, mask, input: Queue = None, output: Queue = None):
        if input is None:
            self.input = Queue()
        else:
            self.input = input

        if output is None:
            self.output = Queue()
        else:
            self.output = output

        self.tun = TunTap(nic_type="Tun", nic_name=tun_name)
        self.tun.config(addr, mask)
        self.addr = str(addr)

        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__sender_proc = threading.Thread(target=self.__sender)

        self.__is_run = True

        self.__receiver_proc.start()
        self.__sender_proc.start()

    def __receiver(self):
        while self.__is_run:
            try:
                buf = self.tun.read()
            except OSError:
                break
            if (buf[0] >> 4) == 4:
                saddr = str(IPv4Address(buf[12:16]))
                daddr = str(IPv4Address(buf[16:20]))
                if saddr == self.addr:
                    self.output.put((buf, daddr))

    def __sender(self):
        while self.__is_run:
            try:
                buf, local_addr = self.input.get(timeout=1)
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

        self.LADDR2ID = {}
        self.ID2LADDR = {}

        self.update_peers(peers)

        self.is_run = True

        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__send_search_proc = threading.Thread(target=self.__send_search)
        self.__send_annonce_proc = threading.Thread(target=self.__send_annonce)

        self.__receiver_proc.start()
        self.__send_search_proc.start()
        self.__send_annonce_proc.start()

    def update_peers(self, peers):
        for peer in peers:
            peer_id = peer.get("id")
            peer_addr = peer.get("addr")

            self.ID2LADDR[peer_id] = peer_addr
            self.LADDR2ID[peer_addr] = peer_id

    def __send_search(self):
        while self.is_run:
            for peer_id in self.ID2LADDR:
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

            self.ID2DADDR[id] = (addr, port)
            self.DADDR2ID[(addr, port)] = id


class Peer:
    def __init__(self, peer_id, peers, serv_addr, ser_port, local_addr=None, local_port=None, input=None, output=None):
        if input is None:
            self.input = Queue()
        else:
            self.input = input

        if output is None:
            self.output = Queue()
        else:
            self.output = output

        self.peer_id = str(peer_id)
        self.peers = peers
        self.server_addr = str(serv_addr)
        self.server_port = int(ser_port)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if local_addr is not None and local_port is not None:
            self.sock.bind((local_addr, local_port))

        self.routeSearch = RouteSearch(serv_addr, ser_port, peer_id, peers, self.sock)

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__sender_proc = threading.Thread(target=self.__sender)

        self.__receiver_proc.start()
        self.__sender_proc.start()

    def __receiver(self):
        while self.__is_run:
            packet, addr = self.sock.recvfrom(10240)
            if addr[0] == self.server_addr and addr[1] == self.server_port:
                self.routeSearch.input.put(packet)
                continue
            peer_id = self.routeSearch.DADDR2ID.get(addr)
            if peer_id is None:
                continue

            local_addr = self.routeSearch.ID2LADDR.get(peer_id)
            if local_addr is None:
                continue
            self.output.put((packet, local_addr))

    def __sender(self):
        while self.__is_run:
            packet, addr = self.input.get()

            peer_id = self.routeSearch.LADDR2ID.get(addr)
            if peer_id is None:
                print(f"packet to {addr} peer id not fount")
                continue

            daddr = self.routeSearch.ID2DADDR.get(peer_id)
            if daddr is None:
                print(f"packet to {addr} destination addr not fount")
                continue
            self.sock.sendto(packet, daddr)


peer = Peer(PEER_ID, net_config.get("peers"), SERVER_ADDR, SERVER_PORT, LOCAL_ADDR, LOCAL_PORT)

#tun_control = TUNControl(tun_name=TUN_NAME, addr=PEER_ADDR, mask=net_config.get("mask"),
#                         input=peer.output, output=peer.input)

#print(tun_control.tun.name, tun_control.tun.ip, tun_control.tun.mask)


def signal_handler(sig, frame):
    print('pressed Ctrl+C, exiting.')
    #tun_control.stop()
    time.sleep(1)
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

while True:
    #print("-----------------------------------LADDR 2 ID")
    #for e in peer.routeSearch.LADDR2ID:
    #    print(f"{e} | {peer.routeSearch.LADDR2ID.get(e)}")
    #print("-----------------------------------ID 2 LADDR")
    #for e in peer.routeSearch.ID2LADDR:
    #    print(f"{e} | {peer.routeSearch.ID2LADDR.get(e)}")
    #print("-----------------------------------DADDR 2 ID")
    #for e in peer.routeSearch.DADDR2ID:
    #    print(f"{e} | {peer.routeSearch.DADDR2ID.get(e)}")
    #print("-----------------------------------ID 2 DADDR")
    #for e in peer.routeSearch.ID2DADDR:
    #    print(f"{e} | {peer.routeSearch.ID2DADDR.get(e)}")
    print(peer.output.get())


