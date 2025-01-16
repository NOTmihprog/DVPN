import time
from Modules.api import ConnectorUnix

con = ConnectorUnix("/tmp/test.sock")
sock_addr = "/tmp/dvpn.sock"

send_to = "emil"

con.send({"type": "close"}, sock_addr)
time.sleep(1)
print(con.recv())

def close():
    con.send({"type": "close"}, sock_addr)
    time.sleep(1)
    con.close()

def get(req, peer_id=None):
    con.send({"type": "get", "id": "test", "req": req, "peer_id": peer_id}, sock_addr)
    packet, addr = con.recv()
    if packet.get("type") == "res":
        return packet.get("res")
    else:
        return "error"

con.send({"type": "init", "name": "TestApp"}, sock_addr)
peers = get("peers")

send_to_peer_id = None
for peer in peers:
    peer_name = get("peer_name", peer)
    if get("peer_name", peer) == send_to:
        send_to_peer_id = peer

if send_to_peer_id is None:
    print("no name error")
    close()
    exit()

con.send({"type": "route", "id": "test", "req": "reg", "route": 50}, sock_addr)

while True:
    try:
        packet, addr = con.recv()
        if packet.get("type") == "ping":
            con.send({"type": "pong"}, sock_addr)
        print(packet, addr)
        con.send({"type": "net", "rou": 50, "pack": b"pidor", "peer_id": send_to_peer_id}, sock_addr)
    except KeyboardInterrupt:
        break
time.sleep(1)


#peers = get("peers")

#for peer in peers:
#    print(peer, get("peer_name", peer), get("peer_addr", peer), get("peer_crypto", peer), get("peer_sub_args", peer))

#time.sleep(1)




#time.sleep(1)
close()
