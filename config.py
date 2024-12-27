__author__ = "mihprog"

__license__ = "GPL"
__version__ = "1.1.4"

__email__ = "mih@mihprog.com"
__status__ = "Development"

import os
import sys
import logging
from colorama import Fore, Style

import configparser


if getattr(sys, 'frozen', False):
    ROOT_DIR = os.path.dirname(os.path.abspath(sys.executable))
elif __file__:
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
else:
    logging.critical(f"Error, ROOT_DIR not found")
    sys.exit(1)

CONFIG_FILE_NAME = 'config.ini'
CONFIG_FILE_PATH = os.path.join(ROOT_DIR, CONFIG_FILE_NAME)


LOG_FORMAT = (f"{Style.NORMAL + Fore.LIGHTGREEN_EX}|"
              f"{Fore.CYAN + Style.DIM}%(asctime)s{Style.NORMAL + Fore.LIGHTGREEN_EX}|{Style.RESET_ALL} "
              f"%(levelname)s {Fore.LIGHTGREEN_EX}|{Fore.LIGHTYELLOW_EX}->{Style.RESET_ALL} "
              f"{Style.NORMAL + Fore.LIGHTWHITE_EX}%(message)s{Style.RESET_ALL}")


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
    def __init__(self, config):
        self.server_addr = config.get("ServerAddr")
        if self.server_addr is None:
            raise ItemNotFoundError("ServerAddr")

        try:
            self.server_port = int(config.get("ServerPort"))
        except ValueError:
            raise ItemNotEqualError("ServerPort", int)
        except TypeError:
            raise ItemNotFoundError("ServerPort")

        self.peer_id = str(config.get("PeerId"))
        if self.peer_id is None:
            raise ItemNotFoundError("PeerId")
        elif len(self.peer_id) != 32:
            raise ItemLenNotEqualError("PeerId", 32)
        try:
            bytes.fromhex(self.peer_id)
        except ValueError:
            raise ItemNotEqualError("ServerPort", "hex")

        self.bind_addr = str(config.get("BindAddr"))
        if self.bind_addr is None:
            raise ItemNotFoundError("BindAddr")

        self.bind_port_range = str(config.get("BindPort"))
        if self.bind_port_range is None:
            raise ItemNotFoundError("BindPort")
        try:
            self.bind_port_range = int(self.bind_port_range)
            self.bind_port_range = (self.bind_port_range, self.bind_port_range)
        except ValueError:
            try:
                self.bind_port_range = self.bind_port_range.split("-")
                self.bind_port_range = (int(self.bind_port_range[0]), int(self.bind_port_range[1]))
            except ValueError:
                raise ItemNotValidError("BindPort")


class NetConfig:
    def __init__(self, config):
        self.name = config.get("TunName")
        if self.name is None:
            raise ItemNotFoundError("TunName")
        try:
            self.mtu = int(config.get("MTU"))
        except ValueError:
            raise ItemNotEqualError("MTU", int)
        except TypeError:
            raise ItemNotFoundError("MTU")

        self.addr = config.get("Addr")
        if self.addr is None:
            raise ItemNotFoundError("Addr")

        self.mask = config.get("Mask")
        if self.mask is None:
            raise ItemNotFoundError("Mask")


class AppConfig:
    def __init__(self, config):
        self.peer_file = config.get("PeerFile")
        if self.peer_file is None:
            raise ItemNotFoundError("PeerFile")
        self.peer_file = os.path.join(ROOT_DIR, self.peer_file)

        self.log_level = str(config.get("LogLevel")).lower()
        if self.log_level == "none":
            self.log_level = logging.INFO

        elif self.log_level == "debug":
            self.log_level = logging.DEBUG

        elif self.log_level == "info":
            self.log_level = logging.INFO

        elif self.log_level == "warning":
            self.log_level = logging.WARNING

        elif self.log_level == "error":
            self.log_level = logging.ERROR

        elif self.log_level == "critical":
            self.log_level = logging.CRITICAL

        else:
            raise ItemNotValidError(self.log_level)


class Config:
    def __init__(self, path: str):
        self.__config = configparser.ConfigParser()
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
            logging.critical(f"Error, [NET] not found in {CONFIG_FILE_NAME}")
            sys.exit(1)
        except ItemError as e:
            e.critical_exit("NET", CONFIG_FILE_NAME)
        try:
            self.app = AppConfig(self.__config["App"])
        except KeyError:
            logging.critical(f"Error, [App] not found in {CONFIG_FILE_NAME}")
            sys.exit(1)
        except ItemError as e:
            e.critical_exit("App", CONFIG_FILE_NAME)
