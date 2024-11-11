#!/usr/bin/env python

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
from logging.handlers import QueueHandler
from queue import Queue
import colorama
import config

from Peer.peer import Peer
from TUN.tun import TUNControl
from Modules.crypto import SymmetricCrypto

from UI.TextUI import TextApp
from UI.TUI import TUIApp


class UAPI:
    def __init__(self, conf, log_queue=None):
        self.conf = conf
        self.log_queue = log_queue
        self.peers = self.conf.net_config.get("peers")

        self.peer = Peer(peer_id=self.conf.PEER_ID, serv_addr=self.conf.SERVER_ADDR,
                         serv_port=self.conf.SERVER_PORT, local_addr=self.conf.LOCAL_ADDR,
                         local_ports=self.conf.LOCAL_PORT_RANGE)

        self.crypto = SymmetricCrypto(peer_id=self.conf.PEER_ID,
                                      dec_in=self.peer.output, enc_out=self.peer.input)

        self.tun_control = TUNControl(tun_name=self.conf.TUN_NAME, addr=self.conf.PEER_ADDR,
                                      mask=self.conf.net_config.get("mask"),
                                      input=self.crypto.dec_out, output=self.crypto.enc_in, peer_id=self.conf.PEER_ID)

    def stop(self):
        self.tun_control.stop()
        self.peer.stop()
        self.crypto.stop()

    def get_peers(self):
        return self.peers

    def get_endpoint(self, peer_id):
        return self.peer.get_peer_endpoint(peer_id)

    def get_peer_status(self, peer_id):
        return self.peer.is_peer_online(peer_id)

    def get_peer_ping(self, peer_id):
        if self.get_peer_status(peer_id):
            ping = self.peer.get_ping(peer_id)
            if ping is not None:
                return ping
            else:
                return 0
        else:
            return 0

    def get_crypto_status(self, peer_id):
        if self.crypto.is_use_crypto(peer_id):
            return "Symmetric"
        else:
            return "No"

    def get_server_status(self):
        return self.peer.is_serv_online()

    def get_local_addr(self):
        return self.peer.sock.getsockname()

    def add_peer(self, peer):
        """
        :param peer: {"id": "<peer_id>", "addr": "<ip addr>", "key": "<crypto key>"}
        :return:None
        """
        self.tun_control.add_peer(peer)
        self.peer.add_peer(peer)
        self.crypto.add_peer(peer)

    def del_peer(self, peer):
        """
        :param peer: {"id": "<peer_id>", "addr": "<ip addr>", "key": "<crypto key>"}
        :return:None
        """
        self.tun_control.del_peer(peer)
        self.peer.del_peer(peer)
        self.crypto.del_peer(peer)

    def update_peer(self, peer):
        """
        :param peer: {"id": "<peer_id>", "addr": "<ip addr>", "key": "<crypto key>"}
        :return:None
        """
        self.tun_control.update_peer(peer)
        self.crypto.update_peer(peer)


if __name__ == "__main__":
    if config.UI_TYPE is None:
        colorama.init()
        logging.basicConfig(level=config.LOG_LEVEL, stream=sys.stdout, format=config.LOG_FORMAT)
        logging.info("Starting mode: log only")
        app = TextApp(UAPI(config))
        app.run()

    elif config.UI_TYPE == "text":
        colorama.init()
        logging.basicConfig(level=config.LOG_LEVEL, stream=sys.stdout, format=config.LOG_FORMAT)
        logging.info("Starting mode: TextUI")
        app = TextApp(UAPI(config))
        app.run()

    elif config.UI_TYPE == "tui":
        log_queue = Queue()
        logging.basicConfig(level=config.LOG_LEVEL, handlers=[QueueHandler(log_queue)], format=config.LOG_FORMAT)
        app = TUIApp(UAPI(conf=config, log_queue=log_queue))
        logging.info("Starting mode: TextUI")
        app.run()

    else:
        colorama.init()
        logging.basicConfig(level=config.LOG_LEVEL, stream=sys.stdout, format=config.LOG_FORMAT)
        logging.critical("UI Type not found")
        sys.exit(1)
