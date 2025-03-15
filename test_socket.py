import random
import time
import threading
import socket
import os

from Modules.utils import Pipe, PipeConn, PipeEmpty
from Modules.router import Router


class Transceiver(threading.Thread):
    def __init__(self, sock, pipe: PipeConn):
        super().__init__()
        self.sock = sock
        self.pipe = pipe
        self.daemon = True
        self.tx_bytes = 0
        self.tx_packets = 0
        self.start()

    def run(self):
        while True:
            try:
                packet, addr = self.pipe.recv(timeout=1)
            except PipeEmpty:
                continue
            try:
                self.sock.sendto(packet, addr)
            except PermissionError:
                continue
            except OSError:
                continue
            else:
                self.tx_bytes += len(packet)
                self.tx_packets += 1


class Receiver(threading.Thread):
    def __init__(self, sock, pipe: PipeConn):
        super().__init__()
        self.sock = sock
        self.pipe = pipe
        self.daemon = True
        self.rx_bytes = 0
        self.rx_packets = 0
        self.start()

    def run(self):
        while True:
            try:
                packet, addr = self.sock.recvfrom(65507)
            except BlockingIOError:
                continue
            except OSError:
                continue
            self.rx_bytes += len(packet)
            self.rx_packets += 1
            self.pipe.send((packet, addr))


class Connector:
    def __init__(self, pipe: PipeConn, sock):
        self.pipe = pipe
        sock.setblocking(True)
        self.transceiver = Transceiver(sock, pipe)
        self.receiver = Receiver(sock, pipe)

    def get_rx_bytes(self) -> int:
        return self.receiver.rx_bytes

    def get_tx_bytes(self) -> int:
        return self.transceiver.tx_bytes

    def get_rx_packets(self) -> int:
        return self.receiver.rx_packets

    def get_tx_packets(self) -> int:
        return self.transceiver.tx_packets


class ConnectorInet(Connector):
    def __init__(self, pipe: PipeConn, bind_addr: tuple[str, int]):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__sock.bind(bind_addr)

        super().__init__(pipe, self.__sock)


class ConnectorUnix(Connector):
    def __init__(self, pipe: PipeConn, bind_addr: str):
        if os.path.exists(bind_addr):
            os.remove(bind_addr)
        self.__sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.__sock.bind(bind_addr)

        super().__init__(pipe, self.__sock)


inet = True
packets = 20
minsize = 120
maxsize = 1500
random_size = False


pipe1, pipe2 = Pipe()
#router1 = Router(pipe=pipe1)
#router2 = Router(pipe=pipe2)

if inet:
    local_con = ConnectorInet(bind_addr=("127.0.0.1", 9043), pipe=pipe1)
    local_con2 = ConnectorInet(bind_addr=("127.0.0.1", 9044), pipe=pipe2)
    # os.system("chmod -w /tmp/notpidor.sock")
    for i in range(packets):
        local_con.pipe.send((random.randbytes(
            random.randint(minsize, maxsize) if random_size else maxsize), ("127.0.0.1", 9044)))
        local_con2.pipe.send((random.randbytes(
            random.randint(minsize, maxsize) if random_size else maxsize), ("127.0.0.1", 9043)))
else:
    local_con = ConnectorUnix(bind_addr="/tmp/test1.s", pipe=pipe1)
    local_con2 = ConnectorUnix(bind_addr="/tmp/test2.s", pipe=pipe2)
    #os.system("chmod -w /tmp/notpidor.sock")
    for i in range(packets):
        local_con.pipe.send((random.randbytes(
            random.randint(minsize, maxsize) if random_size else maxsize), "/tmp/test2.s"))
        #local_con2.pipe.send((b"h" * 1500, ("127.0.0.1", 9003)))


def clear():
    # for windows
    if os.name == 'nt':
        _ = os.system('cls')
    # for mac and linux(here, os.name is 'posix')
    else:
        _ = os.system('clear')


tx = 0
rx = 0
last_tx = 0
last_rx = 0
rx_packets = 0
tx_packets = 0
last_rx_packets = 0
last_tx_packets = 0
tab = 2
while True:
    time.sleep(1)
    clear()
    print("LocalCon:")
    rx = local_con.get_rx_bytes()
    tx = local_con.get_tx_bytes()
    print(" " * tab, "rx:", rx / 1000000, "MB")
    print(" " * tab, "tx:", tx / 1000000, "MB")
    print(" " * tab, "rx speed:", (rx-last_rx) / 1000000, "MB/S")
    print(" " * tab, "tx speed:", (tx-last_tx) / 1000000, "MB/S")
    last_rx = rx
    last_tx = tx
    print()
    rx_packets = local_con.get_rx_packets()
    tx_packets = local_con.get_tx_packets()
    print(" " * tab, "rx_packets:", rx_packets)
    print(" " * tab, "tx_packets:", tx_packets)
    print(" " * tab, "rx_packets/s:", rx_packets-last_rx_packets, "P/S")
    print(" " * tab, "tx_packets/s:", tx_packets-last_tx_packets, "P/S")
    last_rx_packets = rx_packets
    last_tx_packets = tx_packets
