import config
from Modules.peer_storage import PeerListFromFile

conf = config.Config(config.CONFIG_FILE_PATH)

print("CONFIG_FILE_NAME:", config.CONFIG_FILE_NAME)
print()
print("Peer")
print("ServerAddr:", conf.peer.server_addr)
print("ServerPort:", conf.peer.server_port)
print()
print("PeerId:", conf.peer.peer_id)
print("BindAddr:", conf.peer.bind_addr)
print("BindPort:", conf.peer.bind_port_range)
print()
print("NET")
print("TunName:", conf.net.name)
print("MTU:", conf.net.mtu)
print("Addr:", conf.net.addr)
print("Mask:", conf.net.mask)
print()
print("App")
print("PeerFile:", conf.app.peer_file)
print("LogLevel:", conf.app.log_level)
print()


def add_peer(peer_id: str, addr=None, key=None):
    print('add_peer:', peer_id, addr, key)
    print("_"*15, " "*30, "_"*15)


def del_peer(peer_id: str, addr=None, key=None):
    print('del_peer:', peer_id, addr, key)
    print("_" * 15, " " * 30, "_" * 15)


def update_peer(peer_id: str, addr=None, key=None):
    print('update_peer:', peer_id, addr, key)
    print("_" * 15, " " * 30, "_" * 15)


peer_list = PeerListFromFile(conf.app.peer_file, conf.peer.peer_id, add_peer=add_peer, del_peer=del_peer,
                             update_peer=update_peer)

peer_list.load_file()