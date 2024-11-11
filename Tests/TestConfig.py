import config
from PeerList.file import PeerListFromFile

print("CONFIG_FILE_NAME:", config.CONFIG_FILE_NAME)
print()
print("SearchServer")
print("SERVER_ADDR:", config.SERVER_ADDR)
print("SERVER_PORT:", config.SERVER_PORT)
print()
print("Peer")
print("PEER_ID:", config.PEER_ID)
print("LOCAL_ADDR:", config.LOCAL_ADDR)
print("LOCAL_PORT_RANGE:", config.LOCAL_PORT_RANGE)
print()
print("PeerList")
print("PEER_FILE:", config.PEER_FILE)
print()
print("NET")
print("TUN_NAME:", config.TUN_NAME)
print("NET_ADDR:", config.NET_ADDR)
print("NET_MASK:", config.NET_MASK)
print()
print("UI")
print("UI_TYPE:", config.UI_TYPE)
print("LOG_LEVEL:", config.LOG_LEVEL)
print()


def add_peer(peer):
    print('add_peer:', peer)


def del_peer(peer):
    print('del_peer:', peer)


def update_peer(peer):
    print('update_peer:', peer)


peer_list = PeerListFromFile(config.PEER_FILE, add_peer=add_peer, del_peer=del_peer, update_peer=update_peer)

peer_list.load_file()