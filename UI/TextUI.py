__author__ = "mihprog"

__license__ = "GPL"
__version__ = "1.1.4"

__email__ = "mih@mihprog.com"
__status__ = "Production"

import os
import time
import signal
from tabulate import tabulate
import logging


class TextApp:
    def __init__(self, ui_api):
        self.ui_api = ui_api
        self.is_run = True
        self.table_headers = ["Peer ID", "Local", "Endpoint", "Crypto", "Status", "Ping"]
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        if self.is_run:
            logging.info(' Pressed Ctrl+C, exiting.')
            self.is_run = False
            self.ui_api.stop()
        else:
            logging.info(" Exiting in progress...")

    @staticmethod
    def clear():
        # for windows
        if os.name == 'nt':
            _ = os.system('cls')
        # for mac and linux(here, os.name is 'posix')
        else:
            _ = os.system('clear')

    def run(self):
        while self.is_run:
            if self.ui_api.conf.UI_TYPE is None:
                time.sleep(1)
                continue
            table_data = []
            for peer_data in self.ui_api.get_peers():
                peer_id = peer_data.get("id")
                endpoint = self.ui_api.get_endpoint(peer_id)
                if endpoint is not None:
                    endpoint = f"{endpoint[0]}:{endpoint[1]}"

                peer_online = self.ui_api.get_peer_status(peer_id)
                ping = self.ui_api.get_peer_ping(peer_id)
                if peer_id == self.ui_api.conf.PEER_ID:
                    peer_status = "Self"
                    ping = "~"
                elif peer_online:
                    peer_status = "Online"
                else:
                    peer_status = "Offline"
                    ping = 0

                crypto_status = self.ui_api.get_crypto_status(peer_id)

                table_data.append([
                    peer_id, peer_data.get("addr"), endpoint, crypto_status, peer_status, ping])

            serv_online = self.ui_api.get_server_status()
            if serv_online is None:
                server_status = "Connecting"
            elif serv_online:
                server_status = "Online"
            else:
                server_status = "Offline"

            peer_bind = self.ui_api.get_local_addr()
            hed = f"{self.ui_api.conf.PEER_ID} | {peer_bind[0]}:{peer_bind[1]} | Server status: {server_status}"
            self.clear()
            print(hed)
            print("-" * len(hed), "\n")
            print(tabulate(table_data, headers=self.table_headers), "\n")
            time.sleep(1)
