import time
from Modules.api import ConnectorUnix

con = ConnectorUnix("/tmp/test.sock")
sock_addr = "/tmp/dvpn.sock"

con.send({"type": "close"}, sock_addr)
time.sleep(1)
print(con.recv())

con.send({"type": "init", "name": "TestApp"}, sock_addr)


#while True:
#    try:
#        packet, addr = con.recv()
#        if packet.get("type") == "ping":
#            con.send({"type": "pong"}, sock_addr)
#        print(packet, addr)
#    except KeyboardInterrupt:
#        break
#time.sleep(1)

def get(req, peer_id=None):
    con.send({"type": "get", "id": "test", "req": req, "peer_id": peer_id}, sock_addr)
    packet, addr = con.recv()
    if packet.get("type") == "res":
        return packet.get("res")
    else:
        return "error"

#peers = get("peers")

#for peer in peers:
#    print(peer, get("peer_name", peer), get("peer_addr", peer), get("peer_crypto", peer), get("peer_sub_args", peer))

time.sleep(1)

con.send({"type": "route", "id": "test", "req": "reg", "route": 50}, sock_addr)
print(con.recv())
#con.send({"type": "route", "id": "test", "req": "del", "route": 50}, sock_addr)
#print(con.recv())


time.sleep(1)

con.send({"type": "close"}, sock_addr)
time.sleep(1)
con.close()