__author__ = "mihprog"

__license__ = "GPL"
__version__ = "2.0.0"

__email__ = "mih@mihprog.com"
__status__ = "Production"

import typing

from TUN.tuntap import TunTap
from ipaddress import IPv4Address
from Modules.utils import PipeConn, PipeEmpty, ModuleInitError
from Modules.peer_storage import PeerConfigStorage
import threading
import logging


class TUNControl:
    __slots__ = ("pipe", "__peer_storage", "ID2LADDR", "LADDR2ID", "mtu", "addr", "tun", "__receiver_proc",
                 "__sender_proc", "__is_run")
    def __init__(self,
                    tun_name: str,
                    peer_storage: PeerConfigStorage,
                    mask: str,
                    pipe: PipeConn,
                    mtu: typing.Optional[int]=None
                 ):
        self.pipe = pipe
        self.__peer_storage = peer_storage

        self.ID2LADDR = {}
        self.LADDR2ID = {}
        self.mtu = mtu if mtu is not None else 1500

        self.addr = self.__peer_storage.get_peer_addr(self.__peer_storage.peer_id)


        for peer_id in self.__peer_storage.get_peers_id():
            peer_addr = self.__peer_storage.get_peer_addr(peer_id)
            if peer_addr is None:
                continue
            self.__event_handler("add", peer_id, peer_addr)
        self.__peer_storage.add_listener(self.__event_handler)

        try:
            self.tun = TunTap(nic_type="Tun", nic_name=tun_name)
            self.tun.config(self.addr, mask, mtu=self.mtu)
        except Exception as e:
            raise ModuleInitError(f"Tun init error: {e}")


        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__sender_proc = threading.Thread(target=self.__sender)

        self.__is_run = True

        self.__receiver_proc.start()
        self.__sender_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")
    
    
    def __event_handler(self, action, peer_id, addr):
        match action:
            case "add":
                self.ID2LADDR[peer_id] = addr
                self.LADDR2ID[addr] = peer_id
                
            case "del":
                peer_addr = self.ID2LADDR.get(peer_id)
                if peer_addr is None:
                    logging.debug(f"{self.__class__.__name__} | Del peer error: peer_addr is None")
                    return False
                self.LADDR2ID[peer_addr] = None
                self.ID2LADDR[peer_id] = None

            case "update":
                last_addr = self.ID2LADDR.get(peer_id)
                if last_addr is None:
                    logging.debug(f"{self.__class__.__name__} | Update peer error: last_addr is None")
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
            self.pipe.send((buf, peer_id))
        logging.info(f"{self.__class__.__name__} | Thread receiver - stopped")

    def __sender(self):
        logging.info(f"{self.__class__.__name__} | Thread sender - started")
        while self.__is_run:
            try:
                buf, peer_id = self.pipe.recv(timeout=1)
            except PipeEmpty:
                continue
            try:
                self.tun.write(buf)
            except OSError:
                logging.warning(f"{self.__class__.__name__} | Thread sender - tun dev write error")
        logging.info(f"{self.__class__.__name__} | Thread sender - stopped")

    def stop(self, join=False):
        self.__is_run = False
        try:
            if join:
                self.__sender_proc.join()

            self.__receiver_proc.join()
            self.tun.close()
        except AttributeError:
            pass
        logging.info(f"{self.__class__.__name__} | Full - stopped")
