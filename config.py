__author__ = "mihprog"

__license__ = "GPL"
__version__ = "2.0.0"

__email__ = "mih@mihprog.com"
__status__ = "Production"

import base64
import ipaddress
import os
import random
import sys
import logging
from typing import Optional
from colorama import Fore, Style

from Modules.utils import PeerId

from commentedconfigparser import CommentedConfigParser

if getattr(sys, 'frozen', False):
    ROOT_DIR = os.path.dirname(os.path.abspath(sys.executable))
elif __file__:
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
else:
    logging.critical(f"Error, ROOT_DIR not found")
    sys.exit(1)

CONFIG_FILE_NAME = 'config.ini'
CONFIG_FILE_PATH = os.path.join(ROOT_DIR, CONFIG_FILE_NAME)

PEERS_FILE_NAME = "peers.cnf"
PEERS_FILE_PATH = os.path.join(ROOT_DIR, PEERS_FILE_NAME)

SOCKET_DEFAULT_DIR = "/run/dvpn"
SOCKET_DEFAULT_ADDR = "127.0.0.1:9902"


PEER_ID_LEN = 32


LOG_FORMAT = (f"{Style.NORMAL + Fore.LIGHTGREEN_EX}|"
              f"{Fore.CYAN + Style.DIM}%(asctime)s{Style.NORMAL + Fore.LIGHTGREEN_EX}|{Style.RESET_ALL} "
              f"%(levelname)s {Fore.LIGHTGREEN_EX}|{Fore.LIGHTYELLOW_EX}->{Style.RESET_ALL} "
              f"{Style.NORMAL + Fore.LIGHTWHITE_EX}%(message)s{Style.RESET_ALL}")

DEFAULT_CONFIG ="""
[Peer]
# Peer-Id string len = 32, generate: dvpn gen-peer-id
peer-id = {peer_id}

# local bind ip
bind-addr = 0.0.0.0

# local port or port range, exemple: 8647, 8647-9942, 8647-8647
bind-port = 8647-9942

[Server.msk]
# ipv4 address
addr = 62.109.29.213

# udp server port
port = 6485

# server encryption public key in base64 encoding
key = ToltwNlL23RYIzvLk5QdJXE182oaJVYTQAspapIv2dUvGdOHSjHF8E70DWueomspO94x1p3mY5+A

[Server.am]
addr = 103.90.75.155
port = 6485
key = N4SIvT+yilT46KP6sggO/Kc9ZCsTX2jO+fWYo5GdXYBrDv/4A/GPUYHWv/G7IkHSw4bB/BvMDweA


[NET]
# tun interface name, ignored on windows
tun-name = dnet

mtu = 1350
addr = {addr}
mask = 255.255.255.0

[App]
# Log Levels DEBUG, INFO, WARNING, ERROR, CRITICAL
log-level = INFO
"""

def get_random_ip(net):
    net = ipaddress.IPv4Network(net)
    net_list = list(net)
    net_list.remove(net.network_address)
    net_list.remove(net.broadcast_address)
    return random.choice(net_list)

if not os.path.isfile(CONFIG_FILE_PATH):
    try:
        file = open(CONFIG_FILE_PATH, "w")
    except Exception as e:
        logging.critical(f"Create config file error: {e}")
        sys.exit(2)
    file.seek(0)
    file.write(DEFAULT_CONFIG.format(peer_id=PeerId.generate(PEER_ID_LEN), addr=get_random_ip("10.10.33.0/24")))
    file.close()


class ItemError(Exception):
    def __init__(self, name):
        self.name = name

    def critical_exit(self, section, file_name):
        self.log(section, file_name)
        sys.exit(1)

    def log(self, section, file_name):
        logging.critical(f"Error, [{section}] {self.name} error in {file_name}")


class ItemNotFoundError(ItemError):
    def __init__(self, name):
        super().__init__(name)

    def log(self, section, file_name):
        logging.critical(f"Error, [{section}] {self.name} not found in {file_name}")


class ItemNotEqualError(ItemError):
    def __init__(self, name, item_type):
        super().__init__(name)
        self.type = item_type

    def log(self, section, file_name):
        logging.critical(f"Error, [{section}] {self.name} in {file_name} not {self.type}")


class ItemLenNotEqualError(ItemError):
    def __init__(self, name, item_len):
        super().__init__(name)
        self.len = item_len

    def log(self, section, file_name):
        logging.critical(f"Error, [{section}] {self.name} in {file_name} len != {self.len}")


class ItemNotValidError(ItemError):
    def __init__(self, name):
        super().__init__(name)

    def log(self, section, file_name):
        logging.critical(f"Error, [{section}] {self.name} in {file_name} not valid")


class PeerConfig:
    @property
    def peer_id(self) -> str:
        return self.__config.get("peer-id")
    @peer_id.setter
    def peer_id(self, value: str):
        self.__config["peer-id"] = str(value)


    @property
    def bind_addr(self) -> str:
        return self.__config.get("bind-addr")
    @bind_addr.setter
    def bind_addr(self, value: str):
        self.__config["bind-addr"] = str(value)


    @property
    def bind_port_range(self) -> Optional[tuple[int, int]]:
        bind_port = self.__config.get("bind-port")
        try:
            bind_port = int(bind_port)
            return bind_port, bind_port
        except ValueError:
            try:
                bind_port = bind_port.split("-")
                return int(bind_port[0]), int(bind_port[1])
            except ValueError:
                return None
    @bind_port_range.setter
    def bind_port_range(self, value: tuple[int, int]):
        self.__config["bind-port"] = f"{value[0]}-{value[1]}"

    def __init__(self, config):
        self.__config = config

        if self.peer_id is None:
            raise ItemNotFoundError("peer-id")
        elif len(self.peer_id) != PEER_ID_LEN:
            raise ItemLenNotEqualError("peer-id", PEER_ID_LEN)
        try:
            PeerId.validate(self.peer_id)
        except ValueError:
            raise ItemNotValidError("peer-id")

        if self.bind_addr is None:
            raise ItemNotFoundError("bind-addr")
        try:
            ipaddress.IPv4Address(self.bind_addr)
        except ValueError:
            ItemNotValidError("bind-addr")

        if self.bind_port_range is None:
            raise ItemNotValidError("bind-port")


class ServerConfig:
    @property
    def addr(self) -> str:
        return self.__config.get("addr")
    @addr.setter
    def addr(self, value: str):
        self.__config["addr"] = str(value)


    @property
    def port(self) -> Optional[int]:
        try:
            return int(self.__config.get("port"))
        except ValueError:
            return None
    @port.setter
    def port(self, value: int):
        self.__config["port"] = str(value)

    @property
    def key(self) -> Optional[bytes]:
        try:
            return base64.b64decode(self.__config.get("key"))
        except ValueError:
            return None
    @key.setter
    def key(self, value: bytes):
        self.__config["key"] = base64.b64encode(value).decode()

    def __init__(self, config):
        self.__config = config

        if self.addr is None:
            raise ItemNotFoundError("addr")
        try:
            ipaddress.IPv4Address(self.addr)
        except ValueError:
            ItemNotValidError("addr")

        if self.port is None:
            raise ItemNotValidError("port")

        if self.key is None:
            raise ItemNotValidError("key")


class LocalServer:
    @property
    def private_key(self) -> Optional[bytes]:
        try:
            return base64.b64decode(self.__config.get("private-key"))
        except ValueError:
            return None
    @private_key.setter
    def private_key(self, value: bytes):
        self.__config["private-key"] = base64.b64encode(value).decode()

    @property
    def public_key(self) -> Optional[bytes]:
        try:
            return base64.b64decode(self.__config.get("public-key"))
        except ValueError:
            return None
    @public_key.setter
    def public_key(self, value: bytes):
        self.__config["public-key"] = base64.b64encode(value).decode()

    def __init__(self, config):
        self.__config = config


class NetConfig:
    @property
    def name(self) -> str:
        return self.__config.get("tun-name")
    @name.setter
    def name(self, value: str):
        self.__config["tun-name"] = str(value)

    @property
    def mtu(self) -> Optional[int]:
        try:
            return int(self.__config.get("mtu"))
        except ValueError:
            return None
    @mtu.setter
    def mtu(self, value: int):
        self.__config["mtu"] = str(value)

    @property
    def addr(self) -> str:
        return self.__config.get("addr")
    @addr.setter
    def addr(self, value: str):
        self.__config["addr"] = str(value)

    @property
    def mask(self) -> str:
        return self.__config.get("mask")
    @mask.setter
    def mask(self, value: str):
        self.__config["mask"] = str(value)


    def __init__(self, config):
        self.__config = config

        if self.name is None:
            raise ItemNotFoundError("tun-name")

        if self.mtu is None:
            raise ItemNotFoundError("mtu")

        self.addr = config.get("addr")
        if self.addr is None:
            raise ItemNotFoundError("Addr")
        try:
            ipaddress.IPv4Address(self.addr)
        except ValueError:
            ItemNotValidError("addr")

        if self.mask is None:
            raise ItemNotFoundError("Mask")
        try:
            ipaddress.IPv4Address(self.mask)
        except ValueError:
            try:
                int(self.mask)
            except ValueError:
                ItemNotValidError("mask")


class AppConfig:

    @property
    def log_level(self) -> Optional[int]:
        match str(self.__config.get("log-level")).lower():
            case "none":
                return logging.INFO

            case "debug":
                return logging.DEBUG

            case "info":
                return logging.INFO

            case "warning":
                return logging.WARNING

            case "error":
                return logging.ERROR

            case "critical":
                return logging.CRITICAL
            case _:
                return None
    @log_level.setter
    def log_level(self, value: int):
        match value:
            case logging.DEBUG:
                level = "debug"

            case logging.INFO:
                level = "info"

            case logging.WARNING:
                level = "warning"

            case logging.ERROR:
                level = "error"

            case logging.CRITICAL:
                level = "critical"
            case _:
                level = "info"
        self.__config["log-level"] = str(level).upper()

    def __init__(self, config):
        self.__config = config

        if self.log_level is None:
            ItemNotValidError("log-level")


class Config:
    def __init__(self, path: str):
        self.__path = path
        self.__config = CommentedConfigParser()
        self.__config.read(path)

        try:
            self.peer = PeerConfig(self.__config["Peer"])
        except KeyError:
            logging.critical(f"Error, [Peer] not found in {CONFIG_FILE_NAME}")
            sys.exit(1)
        except ItemError as e:
            e.critical_exit("Peer", CONFIG_FILE_NAME)

        try:
            self.net = NetConfig(self.__config["NET"])
        except KeyError:
            logging.info(f"Section [NET] not found in {CONFIG_FILE_NAME} network disabled")
            self.net = None
        except ItemError as e:
            e.critical_exit("NET", CONFIG_FILE_NAME)
        try:
            self.app = AppConfig(self.__config["App"])
        except KeyError:
            logging.critical(f"Error, [App] not found in {CONFIG_FILE_NAME}")
            sys.exit(1)
        except ItemError as e:
            e.critical_exit("App", CONFIG_FILE_NAME)

        try:
            self.local_server = LocalServer(self.__config["LocalServer"])
        except KeyError:
            pass
        except ItemError as e:
            e.critical_exit("App", CONFIG_FILE_NAME)

        self.servers = {}
        for section in self.__config.sections():
            if section.startswith("Server."):
                try:
                    self.servers[section.replace("Server.", "")] = (ServerConfig(self.__config[section]))
                except ItemError as e:
                    e.critical_exit(section, CONFIG_FILE_NAME)

    def create_local_server(self):
        self.__config["LocalServer"] = {}
        self.local_server = LocalServer(self.__config["LocalServer"])

    def save(self):
        try:
            config_file = open(self.__path, "w")
        except PermissionError:
            logging.warning(f"{self.__class__.__name__} | write file({self.__path}) PermissionError")
            return
        config_file.seek(0)
        # noinspection PyTypeChecker
        self.__config.write(config_file)
        config_file.flush()
        config_file.close()
