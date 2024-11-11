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


LOG_FORMAT = (f"{Style.NORMAL + Fore.LIGHTGREEN_EX}|"
              f"{Fore.CYAN + Style.DIM}%(asctime)s{Style.NORMAL + Fore.LIGHTGREEN_EX}|{Style.RESET_ALL} "
              f"%(levelname)s {Fore.LIGHTGREEN_EX}|{Fore.LIGHTYELLOW_EX}->{Style.RESET_ALL} "
              f"{Style.NORMAL + Fore.LIGHTWHITE_EX}%(message)s{Style.RESET_ALL}")


config = configparser.ConfigParser()
config.read(os.path.join(ROOT_DIR, CONFIG_FILE_NAME))
try:
    config_search_server = config["SearchServer"]
except KeyError:
    logging.critical(f"Error, [SearchServer] not found in {CONFIG_FILE_NAME}")
    sys.exit(1)

SERVER_ADDR = config_search_server.get("Addr")
if SERVER_ADDR is None:
    logging.critical(f"Error, [Addr] Addr not found in {CONFIG_FILE_NAME}")
    sys.exit(1)

SERVER_PORT = config_search_server.get("Port")
if SERVER_PORT is None:
    logging.critical(f"Error, [Addr] Port not found in {CONFIG_FILE_NAME}")
    sys.exit(1)
try:
    SERVER_PORT = int(SERVER_PORT)
except ValueError:
    logging.critical(f"Error, [Addr] Port in {CONFIG_FILE_NAME} not int")
    sys.exit(1)

try:
    config_peer = config["Peer"]
except KeyError:
    logging.critical(f"Error, [Peer] not found in {CONFIG_FILE_NAME}")
    sys.exit(1)

PEER_ID = str(config_peer.get("PeerId"))
if PEER_ID is None:
    logging.critical(f"Error, [Peer] PeerId not found in {CONFIG_FILE_NAME}")
    sys.exit(1)
elif len(PEER_ID) != 32:
    logging.critical(f"Error, [Peer] PeerId in {CONFIG_FILE_NAME} len != 32")
    sys.exit(1)

try:
    bytes.fromhex(PEER_ID)
except ValueError:
    logging.critical(f"Error, [Peer] PeerId in {CONFIG_FILE_NAME} not hex")
    sys.exit(1)

LOCAL_ADDR = str(config_peer.get("BindAddr"))
if LOCAL_ADDR is None:
    logging.critical(f"Error, [Peer] BindAddr not found in {CONFIG_FILE_NAME}")
    sys.exit(1)

LOCAL_PORT_RANGE = str(config_peer.get("BindPort"))
if LOCAL_PORT_RANGE is None:
    logging.critical(f"Error, [Peer] BindPort not found in {CONFIG_FILE_NAME}")
    sys.exit(1)
try:
    LOCAL_PORT_RANGE = int(LOCAL_PORT_RANGE)
    LOCAL_PORT_RANGE = (LOCAL_PORT_RANGE, LOCAL_PORT_RANGE)
except ValueError:
    try:
        LOCAL_PORT_RANGE = LOCAL_PORT_RANGE.split("-")
        LOCAL_PORT_RANGE = (int(LOCAL_PORT_RANGE[0]), int(LOCAL_PORT_RANGE[1]))
    except ValueError:
        logging.critical(f"Error, [Peer] BindPort in {CONFIG_FILE_NAME} invalid")
        sys.exit(1)
try:
    config_tun = config["NET"]
except KeyError:
    logging.critical(f"Error, [NET] not found in {CONFIG_FILE_NAME}")
    sys.exit(1)

TUN_NAME = config_tun.get("Name")
if TUN_NAME is None:
    logging.critical(f"Error, [NET] Name not found in {CONFIG_FILE_NAME}")
    sys.exit(1)

NET_ADDR = config_tun.get("Name")
if TUN_NAME is None:
    logging.critical(f"Error, [NET] Name not found in {CONFIG_FILE_NAME}")
    sys.exit(1)

NET_MASK = config_tun.get("Name")
if TUN_NAME is None:
    logging.critical(f"Error, [NET] Name not found in {CONFIG_FILE_NAME}")
    sys.exit(1)


try:
    config_ui = config["UI"]
except KeyError:
    logging.critical(f"Error, [UI] not found in {CONFIG_FILE_NAME}")
    sys.exit(1)

UI_TYPE = str(config_ui.get("Type")).lower()
if UI_TYPE == "none":
    UI_TYPE = None

LOG_LEVEL = str(config_ui.get("LogLevel")).lower()
if LOG_LEVEL == "none":
    LOG_LEVEL = logging.INFO

elif LOG_LEVEL == "debug":
    LOG_LEVEL = logging.DEBUG

elif LOG_LEVEL == "info":
    LOG_LEVEL = logging.INFO

elif LOG_LEVEL == "warning":
    LOG_LEVEL = logging.WARNING

elif LOG_LEVEL == "error":
    LOG_LEVEL = logging.ERROR

elif LOG_LEVEL == "critical":
    LOG_LEVEL = logging.CRITICAL

else:
    logging.critical(f"Error, [UI] LogLevel: '{LOG_LEVEL}' in {CONFIG_FILE_NAME} not recognized")
    sys.exit(1)

