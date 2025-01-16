#!/usr/bin/env python3

__author__ = "mihprog"
__copyright__ = "Copyright 2024, Planet Earth"
__credits__ = ["mihprog", "coffe"]

__license__ = "GPL"
__version__ = "1.1.4"

__maintainer__ = "mihprog"
__email__ = "mih@mihprog.com"
__status__ = "Production"

import sys
import logging
import time
import colorama
import config

from Peer.peer import Peer
from TUN.tun import TUNControl
from Modules.crypto import SymmetricCrypto
from Modules.router import Router
from Modules.utils import Pipe, EventPipe

from PeerConfig.file import PeerListFromFile
from Modules.api import API, ConnectorUnix


class UAPI:
    def __init__(self, conf: config.Config, log_queue=None):
        self.conf = conf
        self.log_queue = log_queue
        self.peer_sub_args_runtime = {}

        self.event_pipe = EventPipe()

        peer_pipe, _peer_pipe = Pipe()

        self.peer = Peer(peer_id=self.conf.peer.peer_id, serv_addr=self.conf.peer.server_addr,
                         serv_port=self.conf.peer.server_port, local_addr=self.conf.peer.bind_addr,
                         local_ports=self.conf.peer.bind_port_range, pipe=_peer_pipe, event_pipe=self.event_pipe)
        crypto_pipe, _crupto_pipe = Pipe()
        self.crypto = SymmetricCrypto(peer_id=self.conf.peer.peer_id, pipe_in=_crupto_pipe, pipe_out=peer_pipe)

        self.router = Router(pipe=crypto_pipe)

        net0_pipe = self.router.register_rote(1)

        self.tun_control = TUNControl(tun_name=self.conf.net.name, addr=self.conf.net.addr,
                                      mask=self.conf.net.mask, mtu=self.conf.net.mtu,
                                      pipe=net0_pipe, peer_id=self.conf.peer.peer_id)

        self.peer_list = PeerListFromFile(conf.app.peer_file, self.conf.peer.peer_id,
                                          add_peer=self.add_peer,
                                          del_peer=self.del_peer,
                                          update_peer=self.update_peer)

    def stop(self):
        self.tun_control.stop()
        self.peer.stop()
        self.crypto.stop()
        self.router.stop()

    def get_peers(self):
        return self.peer_list.peer_list

    def get_peer_name(self, peer_id):
        return self.peer_list.peer_name.get(peer_id)

    def get_peer_addr(self, peer_id):
        return self.peer_list.peer_addr.get(peer_id)

    def get_peer_crypto(self, peer_id):
        return self.peer_list.peer_crypto.get(peer_id)

    def get_peer_sub_args(self, peer_id):
        return self.peer_list.peer_sub_args.get(peer_id)

    def get_peer_sub_arg(self, peer_id, arg):
        args = self.peer_list.peer_sub_args.get(peer_id)
        if type(args) is dict:
            return args.get(arg)

    def get_endpoint(self, peer_id):
        return self.peer.api.get_peer_endpoint(peer_id)

    def get_peer_status(self, peer_id):
        return self.peer.api.is_peer_online(peer_id)

    def get_peer_ping(self, peer_id):
        if self.get_peer_status(peer_id):
            ping = self.peer.api.get_ping(peer_id)
            if ping is not None:
                return ping
            else:
                return 0
        else:
            return 0

    def get_crypto_status(self, peer_id):
        if self.crypto.is_use_crypto(peer_id):
            return "symmetric"
        else:
            return "no"

    def get_server_status(self):
        return self.peer.api.is_serv_online()

    def get_local_addr(self):
        return self.peer.sock.getsockname()


    def add_peer(self, peer_id: str, addr=None, crypto=None):
        """
        :param peer_id: str, len = 32, hex
        :param addr: str, local ip addr, 192.168.1.1
        :param crypto: {"key": <crypto key>}, base64, len = 32
        :return: None
        """
        if not self.peer.add_peer(peer_id=peer_id):
            logging.warning(f"Peer {peer_id} add to peer failed")

        if addr is not None:
            if not self.tun_control.add_peer(peer_id=peer_id, addr=addr):
                logging.warning(f"Peer {peer_id}, {addr} add to tun_control failed")

        if type(crypto) is dict:
            if not self.crypto.add_peer(peer_id=peer_id, key=crypto.get("key")):
                logging.warning(f"Peer {peer_id} add to crypto failed")
        else:
            logging.info(f"Peer {peer_id} encryption disabled")

    def del_peer(self, peer_id):
        """
        :param peer_id: {"id": "<peer_id>", "addr": "<ip addr>", "key": "<crypto key>"}
        :return: None
        """
        if not self.tun_control.del_peer(peer_id=peer_id):
            logging.warning(f"Peer {peer_id} del from tun_control failed")
        if not self.peer.del_peer(peer_id=peer_id):
            logging.warning(f"Peer {peer_id} del from peer failed")
        if not self.crypto.del_peer(peer_id=peer_id):
            logging.warning(f"Peer {peer_id} del from crypto failed")

    def update_peer(self, peer_id: str, addr=None, crypto=None):
        """
        :param peer_id: str, len = 32, hex
        :param addr: str, local ip addr, 192.168.1.1
        :param crypto: {"key": <crypto key>}, base64, len = 32
        :return: None
        """
        if addr is not None:
            if not self.tun_control.update_peer(peer_id=peer_id, addr=addr):
                logging.warning(f"Peer {peer_id} update to tun_control failed")

        if type(crypto) is dict:
            if not self.crypto.update_peer(peer_id=peer_id, key=crypto.get("key")):
                logging.warning(f"Peer {peer_id} update to crypto failed")


if __name__ == "__main__":
    colorama.init()
    conf = config.Config(config.CONFIG_FILE_PATH)
    logging.basicConfig(level=conf.app.log_level, stream=sys.stdout, format=config.LOG_FORMAT)
    logging.info("Starting mode: log only")
    uapi = UAPI(conf)

    con = ConnectorUnix("/tmp/dvpn.sock")
    api = API(con, uapi, uapi.router.register_range(32, 255))
    uapi.event_pipe.reg_event(api.event_handler)

    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break
    uapi.stop()

