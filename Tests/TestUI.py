#!/usr/bin/env python

__author__ = "mihprog"
__copyright__ = "Copyright 2024, Planet Earth"
__credits__ = ["mihprog", "coffe"]

__license__ = "GPL"
__version__ = "1.1.4"

__maintainer__ = "mihprog"
__email__ = "mih@mihprog.com"
__status__ = "Production"

import random
import sys
import logging
from logging.handlers import QueueHandler
from queue import Queue
import colorama
import config

from UI.TextUI import TextApp
from UI.TUI import TUIApp
from PeerList.file import PeerListFromFile


class UAPI:
    def __init__(self, conf, log_queue=None):
        self.conf = conf
        self.log_queue = log_queue

        self.peer_list = PeerListFromFile(config.PEER_FILE, self.conf.PEER_ID, add_peer=self.add_peer,
                                          del_peer=self.del_peer, update_peer=self.update_peer)

    def stop(self):
        pass

    def get_peers(self):
        return self.peer_list.peer_list

    def get_endpoint(self, peer_id):
        return ("0.0.0.0", 1234)

    def get_peer_status(self, peer_id):
        return bool(random.randint(0, 1))

    def get_peer_ping(self, peer_id):
        return random.randint(2, 100)

    def get_crypto_status(self, peer_id):
        if random.randint(0, 1):
            return "Symmetric"
        else:
            return "No"

    def get_server_status(self):
        return True

    def get_local_addr(self):
        return ("0.0.0.0", 1234)

    def add_peer(self, peer):
        """
        :param peer: {"id": "<peer_id>", "addr": "<ip addr>", "key": "<crypto key>"}
        :return:None
        """
        logging.debug(f"Peer {peer} add test")

    def del_peer(self, peer):
        """
        :param peer: {"id": "<peer_id>", "addr": "<ip addr>", "key": "<crypto key>"}
        :return:None
        """
        logging.debug(f"Peer {peer} del test")

    def update_peer(self, peer):
        """
        :param peer: {"id": "<peer_id>", "addr": "<ip addr>", "key": "<crypto key>"}
        :return:None
        """
        logging.debug(f"Peer {peer} update test")


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
