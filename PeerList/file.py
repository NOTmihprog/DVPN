__author__ = "mihprog"

__license__ = "GPL"
__version__ = "1.1.4"

__email__ = "mih@mihprog.com"
__status__ = "Development"


import json


class PeerListFromFile:
    def __init__(self, file_path, add_peer, del_peer, update_peer):
        self.file_path = file_path

        self.__add_peer = add_peer
        self.__del_peer = del_peer
        self.__update_peer = update_peer

        self.peer_id_list = []
        self.peer_list = []

        self.load_file()

    def load_file(self):
        file = open(self.file_path)
        peer_list = json.load(file)
        file.close()
        for peer in peer_list:
            peer_id = peer.get("id")
            peer_name = str(peer.get("name"))
            peer_addr = peer.get("addr")
            peer_key = peer.get("key")

            if peer_id is None:
                continue
            elif len(peer_id) != 32:
                continue
            else:
                peer_id = str(peer_id)

            try:
                bytes.fromhex(peer_id)
            except ValueError:
                continue

            peer = dict(name=peer_name, id=peer_id, addr=peer_addr, key=peer_key)
            if peer_id in self.peer_id_list:
                self.__update_peer(peer)
            else:
                self.peer_id_list.append(peer_id)
                self.peer_list.append(peer)
                self.__add_peer(peer)

