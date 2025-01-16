__author__ = "mihprog"

__license__ = "GPL"
__version__ = "1.1.4"

__email__ = "mih@mihprog.com"
__status__ = "Development"


import json


class PeerListFromFile:
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

