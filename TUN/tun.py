__author__ = "mihprog"
__copyright__ = "Copyright 2024, Planet Earth"
__credits__ = ["mihprog", "coffe"]

__license__ = "GPL"
__version__ = "1.1.4"

__maintainer__ = "mihprog"
__email__ = "mih@mihprog.com"
__status__ = "Production"

from TUN.tuntap import TunTap
from ipaddress import IPv4Address
from queue import Queue, Empty
import threading
import logging


class TUNControl:
    def __init__(self, tun_name, addr, mask, peer_id, input: Queue = None, output: Queue = None):
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
        self.peer_id = peer_id

        self.tun = TunTap(nic_type="Tun", nic_name=tun_name)
        self.tun.config(addr, mask)
        self.addr = str(addr)

        self.add_peer(dict(id=self.peer_id, addr=self.addr))  # add self peer

        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__sender_proc = threading.Thread(target=self.__sender)

        self.__is_run = True

        self.__receiver_proc.start()
        self.__sender_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")

    def add_peer(self, peer) -> bool:
        """
        :param peer: {"id": "<peer_id>", "addr": "192.168.1.1"}
        :return: ok: True, error: False
        """
        peer_id = peer.get("id")
        addr = peer.get("addr")
        if peer_id is None or addr is None:
            return False
        elif self.ID2LADDR.get(peer_id) is not None or self.LADDR2ID.get(addr) is not None:
            return False

        self.ID2LADDR[peer_id] = addr
        self.LADDR2ID[addr] = peer_id
        return True

    def del_peer(self, peer) -> bool:        
        """
        :param peer: {"id": "<peer_id>"}
        :return: ok: True, error: False
        """
        peer_id = peer.get("id")
        if peer_id is None or peer_id == self.peer_id:
            return False
        addr = self.ID2LADDR.get(peer_id)
        if addr is None:
            return False

        self.LADDR2ID[addr] = None
        self.ID2LADDR[peer_id] = None

    def update_peer(self, peer) -> bool:
        """
        :param peer: {"id": "<peer_id>", "addr": "192.168.1.1"}
        :return: ok: True, error: False
        """
        peer_id = peer.get("id")
        addr = peer.get("addr")
        if peer_id is None or addr is None or peer_id == self.peer_id or self.ID2LADDR.get(peer_id) is None:
            return False

        last_addr = self.ID2LADDR.get(peer_id)
        if last_addr is None:
            return False

        self.LADDR2ID[last_addr] = None
        self.LADDR2ID[addr] = peer_id

    def __receiver(self):
        logging.info(f"{self.__class__.__name__} | Thread receiver - started")
        while self.__is_run:
            try:
                buf = self.tun.read()
            except OSError:
                break

            if buf is None:
                continue

            if (buf[0] >> 4) == 4:
                saddr = str(IPv4Address(buf[12:16]))
                daddr = str(IPv4Address(buf[16:20]))
            else:
                continue

            if saddr != self.addr:
                continue
            peer_id = self.LADDR2ID.get(daddr)
            if peer_id is None:
                logging.debug(f"{self.__class__.__name__} | Packet to {daddr} peer id not found")
                continue
            self.output.put((buf, peer_id))
        logging.info(f"{self.__class__.__name__} | Thread receiver - stopped")

    def __sender(self):
        logging.info(f"{self.__class__.__name__} | Thread sender - started")
        while self.__is_run:
            try:
                buf, peer_id = self.input.get(timeout=1)
            except Empty:
                continue
            try:
                self.tun.write(buf)
            except OSError:
                logging.warning(f"{self.__class__.__name__} | Thread sender - tun dev write error")
        logging.info(f"{self.__class__.__name__} | Thread sender - stopped")

    def stop(self):
        self.__is_run = False
        self.__receiver_proc.join()
        self.__sender_proc.join()
        self.tun.close()
        logging.info(f"{self.__class__.__name__} | Full - stopped")

