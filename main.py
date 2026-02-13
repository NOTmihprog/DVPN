#!/usr/bin/env python3

__author__ = "mihprog"
__copyright__ = "Copyright 2025, Planet Earth"
__credits__ = ["mihprog", "coffe"]

__license__ = "GPL"
__version__ = "2.0.3"

__maintainer__ = "mihprog"
__email__ = "mih@mihprog.com"
__status__ = "Production"

import base64
import ipaddress
import json
import os
import sys
import logging
import time
import colorama
import config
import typer
import socket
import signal
from typing_extensions import Annotated
from tabulate import tabulate

from Peer.peer import Peer
from TUN.tun import TUNControl
from Modules.crypto import SymmetricCrypto
from Modules.router import Router
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from Modules.utils import Pipe, EventPipe, ConnectorUnix, ConnectorInet, PeerLogsHandler, ModuleInitError, PeerId
from Peer.utils import PingUtils
from Server.server import Server

from Modules.peer_storage import PeerConfigStorage
from Modules.api import API


class UAPI:
    def __init__(self, conf: config.Config, peer_storage: PeerConfigStorage, log_queue=None):
        self.conf = conf
        self.__peer_storage = peer_storage
        self.log_queue = log_queue
        self.peer_sub_args_runtime = {}
        try:

            self.event_pipe = EventPipe()

            peer_pipe, _peer_pipe = Pipe()

            servers = []
            for server in self.conf.servers:
                server_conf = conf.servers.get(server)
                servers.append(((server_conf.addr, server_conf.port), server_conf.key))

            self.peer = Peer(peer_storage=self.__peer_storage,event_pipe=self.event_pipe,
                             local_addr=self.conf.peer.bind_addr, local_ports=self.conf.peer.bind_port_range,
                             pipe=_peer_pipe, servers=servers)

            crypto_pipe, _crypto_pipe = Pipe()
            self.crypto = SymmetricCrypto(peer_storage=self.__peer_storage, pipe_in=_crypto_pipe, pipe_out=peer_pipe)

            self.router = Router(pipe=crypto_pipe)

            self.ping_utils = PingUtils(self.__peer_storage, self.router.register_rote(0), self.event_pipe)

            if self.conf.net is not None:
                net0_pipe = self.router.register_rote(1)

                self.tun_control = TUNControl(tun_name=self.conf.net.name, peer_storage=self.__peer_storage,
                                              mask=self.conf.net.mask, mtu=self.conf.net.mtu, pipe=net0_pipe)
        except ModuleInitError as e:
            logging.critical(f"{self.__class__.__name__} | {e}")
            self.stop()
            sys.exit()

    def stop(self):
        try:
            if self.conf.net is not None:
                self.tun_control.stop()
        except Exception as e:
            logging.info(f"{self.__class__.__name__} | NET stop error: {e}")

        try:
            self.peer.stop()
        except Exception as e:
            logging.info(f"{self.__class__.__name__} | PEER stop error: {e}")

        try:
            self.crypto.stop()
        except Exception as e:
            logging.info(f"{self.__class__.__name__} | CRYPTO stop error: {e}")

        try:
            self.router.stop()
        except Exception as e:
            logging.info(f"{self.__class__.__name__} | ROUTER stop error: {e}")

    def get_peer_status(self, peer_id):
        return self.__peer_storage.get_peer_endpoint(peer_id) is not None

    def get_peer_ping(self, peer_id):
        if self.get_peer_status(peer_id):
            return self.ping_utils.det_ping(peer_id)
        else:
            return 0

    def get_crypto_status(self, peer_id):
        if self.crypto.is_use_crypto(peer_id):
            return "symmetric"
        else:
            return "no"

    def get_servers(self):
        servers = []
        for server in self.conf.servers:
            server_conf = self.conf.servers.get(server)
            servers.append((server_conf.addr, server_conf.port))
        return servers

    def get_server_status(self, addr: tuple[str, int]):
        client = self.peer.get_client(addr)
        if client is None:
            return None
        return bool(client.get_server_status())

    def get_server_key(self, addr: tuple[str, int]):
        client = self.peer.get_client(addr)
        if client is None:
            return None
        return client.get_public_key()

    def get_server_last_announce(self, addr: tuple[str, int]):
        client = self.peer.get_client(addr)
        if client is None:
            return None
        return client.last_announce

    def get_server_last_search(self, addr: tuple[str, int]):
        client = self.peer.get_client(addr)
        if client is None:
            return None
        return client.last_search

    def get_server_last_response(self, addr: tuple[str, int]):
        client = self.peer.get_client(addr)
        if client is None:
            return None
        return client.last_response

    def get_local_addr(self):
        return self.peer.get_local_addr()



typer_app = typer.Typer()

def get_peer_id_or_exit(peer_id: str, peer_storage: PeerConfigStorage) -> str:
    if len(peer_id) < config.PEER_ID_LEN:
        peer_id = peer_storage.get_full_peer_id(peer_id)
    else:
        try:
            PeerId.validate(peer_id)
        except ValueError:
            logging.critical(f"Peer_id {peer_id} invalid")
            sys.exit(1)
    if peer_id is None:
        logging.critical(f"Peer_id {peer_id} not found")
        sys.exit(1)
    return peer_id

def write_or_print_or_exit(out, data, onl_json):
    out_data = json.dumps(data)
    if not onl_json:
        out_data = base64.urlsafe_b64encode(out_data.encode()).decode()
    if out is None:
        print(out_data)
    else:
        try:
            file = open(out, "w")
        except Exception as e:
            logging.critical(f"Open file error: {e}")
            sys.exit(1)
        file.seek(0)
        file.write(out_data)
        file.close()

def read_input_or_exit(inp: str) -> any:
    if inp is not None:
        try:
            file = open(inp, "r")
        except Exception as e:
            logging.critical(f"Open file error: {e}")
            sys.exit(1)
        file.seek(0)
        inp_data = file.read()
        file.close()
    else:
        inp_data = input("Paste peers string: ")
    try:
        inp_data = base64.urlsafe_b64decode(inp_data).decode()
    except ValueError:
        pass
    try:
        inp_data = json.loads(inp_data)
    except ValueError:
        logging.critical("Load error")
        sys.exit(1)
    return inp_data

is_run = True

@typer_app.callback(invoke_without_command=True)
def main(ctx: typer.models.Context,
         disable_net: Annotated[bool, typer.Option("--disable-net", "-dn",
                                                help="Disable network interface")] = False,
         api_addr: Annotated[str, typer.Option("--api-addr", "-a",
                                                help="api net socket or unix socket address,"
                                                     " UNIX socket unsupported on windows")] = None,
         version: Annotated[bool, typer.Option("--version", "-v",
                                               help="Print version and exit")] = None,

         ):
    global is_run

    if version:
        print(f"Version: {__version__} | Author: {__author__}\n")
        print(f"Если вам скучно или нужна помощь: {__email__}")
        print(f"+{'-'*47}+")
        print(f"If you are bored or need help: {__email__}\n")
        return

    conf = config.Config(config.CONFIG_FILE_PATH)
    logging.basicConfig(level=conf.app.log_level, stream=sys.stdout,
                        format=config.LOG_FORMAT)
    if disable_net:
        conf.net = None

    peer_storage = PeerConfigStorage(conf.peer.peer_id, config.PEERS_FILE_PATH)

    if conf.net is not None and peer_storage.get_peer_addr(peer_storage.peer_id) is None:
        peer_storage.set_peer(peer_id=peer_storage.peer_id, addr=conf.net.addr)

    if conf.net is not None and peer_storage.get_peer_addr(peer_storage.peer_id) != conf.net.addr:
        conf.net.addr = peer_storage.get_peer_addr(peer_storage.peer_id)
        conf.save()

    if ctx.invoked_subcommand is not None:
        ctx.meta["conf"] = conf
        ctx.meta["peer_storage"] = peer_storage
        return

    if api_addr is None:
        if os.name == 'nt' or conf.net is None:
            api_addr = config.SOCKET_DEFAULT_ADDR
        else:
            try:
                os.mkdir(config.SOCKET_DEFAULT_DIR)
                api_addr = os.path.join(config.SOCKET_DEFAULT_DIR, f"{conf.net.name}.sock")
            except FileExistsError:
                api_addr = os.path.join(config.SOCKET_DEFAULT_DIR, f"{conf.net.name}.sock")
            except PermissionError:
                logging.info(f"Failed create directory: {config.SOCKET_DEFAULT_DIR},"
                                f" Use net socket: {config.SOCKET_DEFAULT_ADDR}")
                api_addr = config.SOCKET_DEFAULT_ADDR

    try:
        ip, port = api_addr.split(":")
        ip = ipaddress.ip_address(ip)
        con = ConnectorInet((str(ip), int(port)))
    except ValueError:
        sock_dir = os.path.split(api_addr)[0]
        if sock_dir == "":
            logging.critical(f"Socket path: invalid value: {api_addr}")
            return
        if not os.path.isdir(sock_dir):
            logging.critical(f"Socket path: directory {sock_dir} not exist")
            return
        if os.name == 'nt':
            logging.critical(f"Failed create UNIX socket {api_addr} windows unsupported UNIX sockets")
            return
        try:
            con = ConnectorUnix(api_addr)
        except IsADirectoryError:
            logging.critical(f"Failed create UNIX socket {api_addr} Is A Directory Error")
            return
        except PermissionError:
            logging.critical(f"Failed create UNIX socket {api_addr} Permission Error")
            return
        except OSError as e:
            logging.critical(f"Failed start UNIX socket {api_addr} OS Error: {e}")
            return
    except PermissionError:
        logging.critical(f"Failed start api on address {api_addr} Permission Error")
        return
    except OSError as e:
        logging.critical(f"Failed start api on address {api_addr} OS Error: {e}")
        return


    logging.basicConfig(level=conf.app.log_level, handlers=[PeerLogsHandler(peer_storage)],
                        format=config.LOG_FORMAT, force=True)

    logging.info("Starting mode: log only")
    if conf.net is None:
        logging.info("Network disabled")

    uapi = UAPI(conf, peer_storage)

    api = API(con, uapi, peer_storage, uapi.router.register_range(32, 255))
    uapi.event_pipe.add_listener(api.event_handler)

    is_run = True

    def signal_handler(sig, frame):
        global is_run
        if sig != signal.SIGINT and frame is None:
            return
        if is_run:
            logging.info(' Pressed Ctrl+C, exiting.')
            uapi.stop()
            api.stop()
            con.close()
            time.sleep(1)
            is_run = False
        else:
            logging.info(" Exiting in progress...")

    signal.signal(signal.SIGINT, signal_handler)

    while is_run:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break

@typer_app.command(help="Generate new peer-id")
def gen_peer_id():
    print(PeerId.generate(config.PEER_ID_LEN))

@typer_app.command(help="Generate new symmetric encryption key")
def gen_key():
    print(base64.urlsafe_b64encode(os.urandom(32)).decode())

@typer_app.command(name="set", help="Set or add peer or peer parameters")
def set_peer(ctx: typer.models.Context,
             peer_id: Annotated[str, typer.Option("--peer-id", "-p",
                                                  help="Peer_id: len 32, format hex, generate: gen-peer-id")],
             name: Annotated[str, typer.Option("--name", "-n",
                                               help="Optional, peer name, str or None to clear")]=None,
             addr: Annotated[str, typer.Option("--addr", "-a",
                                               help="Optional, IPv4 address on lan network")]=None,
             key: Annotated[str, typer.Option("--key", "-k",
                                              help="Optional, Crypto key len 32, format base64, generate: gen-key")]=None,
             clear: Annotated[bool, typer.Option("--clear", "-c",
                                              help="Optional, clean not indicated parameters")] = None,
             set_self: Annotated[bool, typer.Option("--self", "-s",
                                                 help="Optional, set peer_id and net addr as self")] = None
             ):


    peer_storage: PeerConfigStorage = ctx.meta.get("peer_storage")

    peer_id = get_peer_id_or_exit(peer_id, peer_storage)

    peer = peer_storage.get_peer(peer_id)
    if peer is not None:
        if name == "None":
            peer["name"] = None
            name = None

        if addr == "None":
            peer["addr"] = None
            addr = None

        if key == "None":
            peer["crypto"] = None
            key = None
        peer_storage.set_peer(**peer, force=True)
    del peer

    if key is not None:
        try:
            byte_key = base64.urlsafe_b64decode(key)
        except ValueError:
            try:
                byte_key = base64.b64decode(key)
            except ValueError:
                byte_key = None

        if byte_key is not None and len(byte_key) == 32:
            key = base64.urlsafe_b64encode(byte_key).decode()
        else:
            logging.critical(f"key {key} invalid")
            return


    name = None if name == "" else name
    try:
        addr = None if addr is None else str(ipaddress.IPv4Address(addr))
    except ipaddress.AddressValueError as e:
        logging.critical(f"addr invalid, error: {e}")
        return

    peer_storage.set_peer(peer_id, name, addr, crypto={"key": key} if key is not None else None, force=clear)

    if set_self:
        conf = ctx.meta.get("conf")

        conf.peer.peer_id = peer_id
        if conf.net is not None and peer_storage.get_peer_addr(peer_id) is None:
            conf.net.addr = peer_storage.get_peer_addr(peer_id)
        conf.save()
        peer_storage.peer_id = peer_id

    list_peers(ctx)

@typer_app.command(name="del", help="Delete peer by id")
def del_peer(ctx: typer.models.Context,
             peer_id: Annotated[str, typer.Option("--peer-id", "-p",
                                                  help="Peer_id: len 32, format hex")]):
    peer_storage: PeerConfigStorage = ctx.meta.get("peer_storage")

    peer_id = get_peer_id_or_exit(peer_id, peer_storage)
    peer_storage.del_peer(peer_id)
    list_peers(ctx)

@typer_app.command(name="list", help="Show peers table")
def list_peers(ctx: typer.models.Context):
    peer_storage: PeerConfigStorage = ctx.meta.get("peer_storage")
    headers = ["Name", "PeerID", "Addr", "encryption"]
    table = []

    for peer in peer_storage.get_peers():
        crypto = peer.get("crypto")
        table.append([
            f"[{peer.get('name')}]" if peer_storage.peer_is_self(peer.get("peer_id")) else peer.get("name"),
            peer.get("peer_id"),
            peer.get("addr"),
            " ".join(list(f"{key}: {crypto[key]}" for key in crypto)) if crypto is not None else "disabled"
        ])

    print("\n" + tabulate(table, headers, tablefmt="github") + "\n")

@typer_app.command(name="export", help="Export peers to base64 or json")
def export_peers(ctx: typer.models.Context,
                 onl_json: Annotated[bool, typer.Option("--json", "-j",
                                                             help="No encode json to base64")] = False,
                 out: Annotated[str, typer.Option("--output", "-o",
                                                    help="Output file path")] = None
               ):
    peer_storage: PeerConfigStorage = ctx.meta.get("peer_storage")
    peers = []

    for peer in peer_storage.get_peers():
        out_peer = {
            "name": peer.get("name"),
            "peer_id": peer.get("peer_id"),
            "addr": peer.get("addr"),
            "crypto": peer.get("crypto")
        }
        peers.append(out_peer)

    write_or_print_or_exit(out, peers, onl_json)

@typer_app.command(name="import", help="Import peers from base64 or json")
def import_peers(ctx: typer.models.Context,
                 inp: Annotated[str, typer.Option("--input", "-i",
                                                    help="Input file path")] = None,
                 clear_last: Annotated[bool, typer.Option("--clear", "-c",
                                                    help="Clear last peers")] = False
                 ):
    peer_storage: PeerConfigStorage = ctx.meta.get("peer_storage")
    inp_data = read_input_or_exit(inp)

    if clear_last:
        for peer_id in peer_storage.get_peers_id():
            peer_storage.del_peer(peer_id)
    for peer in inp_data:
        if peer.get("peer_id") is None:
            if peer.get("id") is None:
                continue
            else:
                peer_id = peer.get("id")
        else:
            peer_id = peer.get("peer_id")
        peer_storage.set_peer(peer_id, peer.get("name"), peer.get("addr"), peer.get("crypto"), force=True)
    list_peers(ctx)

@typer_app.command(name="export-peer", help="Export peer to base64 or json")
def export_peer(ctx: typer.models.Context,
                peer_id: Annotated[str, typer.Option("--peer-id", "-p",
                                                     help="Optional, peer_id: len 32, format hex,"
                                                          " default: self peer-id")] = None,
                onl_json: Annotated[bool, typer.Option("--json", "-j",
                                                             help="No encode json to base64")] = False,
                out: Annotated[str, typer.Option("--output", "-o",
                                                    help="Output file path")] = None
               ):
    peer_storage: PeerConfigStorage = ctx.meta.get("peer_storage")
    if peer_id is None:
        peer_id = peer_storage.peer_id
    peer_id = get_peer_id_or_exit(peer_id, peer_storage)
    peer = peer_storage.get_peer(peer_id)
    out_peer = {
        "name": peer.get("name"),
        "peer_id": peer.get("peer_id"),
        "addr": peer.get("addr"),
        "crypto": peer.get("crypto")
    }

    write_or_print_or_exit(out, out_peer, onl_json)

@typer_app.command(name="import-peer", help="Import peer from base64 or json")
def import_peer(ctx: typer.models.Context,
                 inp: Annotated[str, typer.Option("--input", "-i",
                                                    help="Input file path")] = None
                 ):
    peer_storage: PeerConfigStorage = ctx.meta.get("peer_storage")

    peer = read_input_or_exit(inp)
    if type(peer) is not dict:
        logging.critical(f"data type != dict, type: {type(peer)}")
        return

    if peer.get("peer_id") is None:
        if peer.get("id") is None:
            logging.critical(f"Peer-id not found in data")
            return
        else:
            peer_id = peer.get("id")
    else:
        peer_id = peer.get("peer_id")
    peer_storage.set_peer(peer_id, peer.get("name"), peer.get("addr"), peer.get("crypto"), force=True)
    list_peers(ctx)

@typer_app.command(name="server", help="Start peer detection server")
def run_server(ctx: typer.models.Context,
                 addr: Annotated[str, typer.Option("--addr", "-a",
                                                       help="Server bind ipv4 addr")] = "0.0.0.0",
                 port: Annotated[int, typer.Option("--port", "-p",
                                                 help="Server bind port")] = 6485,
                 ):
    global is_run
    try:
        ipaddress.IPv4Address(addr)
    except ipaddress.AddressValueError as e:
        logging.critical(f"addr invalid, error: {e}")
        return

    conf: config.Config = ctx.meta.get("conf")
    try:
        if conf.local_server.private_key is None:
            raise AttributeError
    except AttributeError:
        key = Ed448PrivateKey.generate()
        conf.create_local_server()
        conf.local_server.private_key = key.private_bytes_raw()
        conf.local_server.public_key = key.public_key().public_bytes_raw()
        conf.save()
    else:
        key = Ed448PrivateKey.from_private_bytes(conf.local_server.private_key)
        public_key = key.public_key()
        if conf.local_server.public_key != public_key.public_bytes_raw():
            conf.local_server.public_key = public_key.public_bytes_raw()
            conf.save()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((addr, port))
    except Exception as e:
        logging.critical(f"Socket bind error: {e}")
        return
    logging.info(f"Public key: {base64.b64encode(key.public_key().public_bytes_raw()).decode()}")
    server = Server(sock, key.private_bytes_raw(), config.PEER_ID_LEN)
    logging.info(f"Server started listen: {addr}:{port}")

    is_run = True

    def signal_handler(sig, frame):
        global is_run
        if sig != signal.SIGINT and frame is None:
            return
        if is_run:
            logging.info(' Pressed Ctrl+C, exiting.')
            server.stop()
            sock.close()
            time.sleep(1)
            is_run = False
        else:
            logging.info(" Exiting in progress...")

    signal.signal(signal.SIGINT, signal_handler)

    while is_run:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break
    logging.info(f"Server stopped")

if __name__ == "__main__":
    colorama.init()
    typer_app()
