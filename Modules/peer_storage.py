__author__ = "mihprog"

__license__ = "GPL"
__version__ = "1.1.4"

__email__ = "mih@mihprog.com"
__status__ = "Development"


import json
import typing

import msgpack
import logging
import threading

from Modules.utils import EventPipe

class PeerConfigStorage:
    def __init__(self, peer_id: str, file_path: str, mode: str="rw"):
        self.__file_path = file_path
        self.__file_readable = mode.lower().index("r") > -1
        self.__file_writable = mode.lower().index("w") > -1

        self.__event_pipe = EventPipe()

        self.__write_lock = threading.Lock()

        self.__peer_list = []
        self.__peer_name = {}
        self.__peer_addr = {}
        self.__peer_crypto = {}
        self.__peer_sub_args = {}

        self.peer_id = peer_id
        self.__peer_list.append(peer_id)
        self.__read_config()

    def add_listener(self, func):
        self.__event_pipe.add_listener(func)
    def del_listener(self, func):
        self.__event_pipe.del_listener(func)

    def __read_config(self):
        if not self.__file_readable:
            return

        try:
            file = open(self.__file_path, "rb")
        except PermissionError:
            logging.warning(f"{self.__class__.__name__} | read file({self.__file_path}) PermissionError")
            return
        except FileNotFoundError:
            logging.debug(f"{self.__class__.__name__} | file({self.__file_path}) Not Found")
            return
        file.seek(0)
        peer_list = msgpack.Unpacker(file)

        for peer in peer_list:
            try:
                peer_id = str(peer["peer_id"])
            except KeyError:
                logging.warning(f"{self.__class__.__name__} | line {peer} peer_id not found")
                continue
            peer_name = str(peer.get("name"))
            peer_addr = str(peer.get("addr"))
            peer_crypto = peer.get("crypto")
            peer_sub_args = peer.get("args")

            if not peer_id in self.__peer_list:
                self.__peer_list.append(peer_id)

            self.__peer_name[peer_id] = peer_name
            self.__peer_addr[peer_id] = peer_addr
            self.__peer_crypto[peer_id] = peer_crypto
            self.__peer_sub_args[peer_id] = peer_sub_args
        file.close()

    def __write_config(self):
        if not self.__file_writable:
            return
        self.__write_lock.acquire()
        try:
            file = open(self.__file_path, "wb")
        except PermissionError:
            logging.warning(f"{self.__class__.__name__} | write file({self.__file_path}) PermissionError")
            self.__write_lock.release()
            return
        file.seek(0)

        for peer_id in self.__peer_list:
            peer_name = self.__peer_name.get(peer_id)
            peer_addr = self.__peer_addr.get(peer_id)
            peer_crypto = self.__peer_crypto.get(peer_id)
            peer_sub_args = self.__peer_sub_args.get(peer_id)
            file.write(msgpack.packb(dict(peer_id=peer_id, name=peer_name, addr=peer_addr,
                                                 crypto=peer_crypto, args=peer_sub_args)))
        file.flush()
        file.close()
        self.__write_lock.release()

    def set_peer(self,
                    peer_id: str,
                    name: str=None,
                    addr: str=None,
                    crypto: dict[str, any]=None,
                    sub_args: dict[str, any]=None,
                    force: bool=False
                 ):
        event = {}
        if peer_id in self.__peer_list:
            event["event_type"] = "update_peer"
        else:
            self.__peer_list.append(peer_id)
            event["event_type"] = "add_peer"
        event["peer_id"] = peer_id

        if name is not None or force:
            self.__peer_name[peer_id] = name
            event["name"] = name

        if addr is not None or force:
            self.__peer_addr[peer_id] = addr
            event["addr"] = addr

        if crypto is not None or force:
            self.__peer_crypto[peer_id] = crypto
            event["crypto"] = crypto

        if sub_args is not None or force:
            self.__peer_sub_args[peer_id] = sub_args
            event["sub_args"] = sub_args

        self.__event_pipe.event(**event)
        self.__write_config()

    def del_peer(self, peer_id: str):
        event = {}
        if not peer_id in self.__peer_list:
            return False

        self.__peer_list.remove(peer_id)
        event["event_type"] = "del_peer"
        event["peer_id"] = peer_id

        self.__peer_name[peer_id] = None
        self.__peer_addr[peer_id] = None
        self.__peer_crypto[peer_id] = None
        self.__peer_sub_args[peer_id] = None

        event["name"] = None
        event["addr"] = None
        event["crypto"] = None
        event["sub_args"] = None

        self.__event_pipe.event(**event)
        self.__write_config()

    def get_peer(self, peer_id: str) -> typing.Optional[dict[str, any]]:
        if not peer_id in self.__peer_list:
            return None
        peer = {
            "peer_id": peer_id,
            "name": self.__peer_name.get(peer_id),
            "addr": self.__peer_addr.get(peer_id),
            "crypto": self.__peer_crypto.get(peer_id),
            "sub_args": self.__peer_sub_args.get(peer_id)
        }
        return peer

    def get_peers(self) -> list[dict[str, any]]:
        return list(self.get_peer(peer_id) for peer_id in self.__peer_list)

    def get_peers_id(self) -> list[str]:
        return list(self.__peer_list)

    def get_peer_name(self, peer_id: str) -> typing.Optional[str]:
        return self.__peer_name.get(peer_id)

    def get_peer_addr(self, peer_id: str) -> typing.Optional[str]:
        return self.__peer_addr.get(peer_id)

    def get_peer_crypto(self, peer_id: str) -> typing.Optional[dict[str, any]]:
        return self.__peer_crypto.get(peer_id)

    def get_peer_sub_args(self, peer_id: str) -> typing.Optional[dict[str, any]]:
        return self.__peer_sub_args.get(peer_id)

    def get_peer_sub_arg(self, peer_id: str, arg: str) -> typing.Optional[any]:
        args = self.__peer_sub_args.get(peer_id)
        if type(args) is not dict:
            return None
        return args.get(arg)

    def set_peer_sub_arg(self, peer_id: str, arg: str, val: any) -> None:
        if not peer_id in self.__peer_list:
            return None
        try:
            self.__peer_sub_args[peer_id][arg] = val
        except TypeError:
            self.__peer_sub_args[peer_id] = {arg: val}

    def peer_exists(self, peer_id: str) -> bool:
        return peer_id in self.__peer_list

    def peer_is_self(self, peer_id: str) -> bool:
        return peer_id == self.peer_id



class FileLoader:
    def __init__(self, file_path, peer_id, add_peer, del_peer, update_peer):
        self.file_path = file_path

        self.__add_peer = add_peer
        self.__del_peer = del_peer
        self.__update_peer = update_peer

        self.peer_id = peer_id

        self.peer_list = []
        self.peer_name = {}
        self.peer_addr = {}
        self.peer_crypto = {}
        self.peer_sub_args = {}

        self.load_file()

    def load_file(self):
        file = open(self.file_path)
        peer_list = json.load(file)
        file.close()
        for peer in peer_list:
            peer_id = peer.get("id")
            peer_name = str(peer.get("name"))
            peer_addr = peer.get("addr")
            peer_crypto = peer.get("crypto")
            peer_sub_args = peer.get("args")

            if peer_id is None:
                continue
            elif len(peer_id) != 32 or peer_id == self.peer_id:
                continue
            else:
                peer_id = str(peer_id)

            try:
                bytes.fromhex(peer_id)
            except ValueError:
                continue

            if peer_id in self.peer_list:
                self.__update_peer(peer_id=peer_id, addr=peer_addr, crypto=peer_crypto)
            else:
                self.peer_list.append(peer_id)
                self.peer_name[peer_id] = peer_name
                self.peer_addr[peer_id] = peer_addr
                self.peer_crypto[peer_id] = peer_crypto
                self.peer_sub_args[peer_id] = peer_sub_args
                self.__add_peer(peer_id=peer_id, addr=peer_addr, crypto=peer_crypto)
