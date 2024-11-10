import socket
import time
from datetime import datetime, timedelta
import json
from sqlalchemy import create_engine, String, Integer, Column, DateTime
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError


SERVER_ADDP = "127.0.0.1"
SERVER_PORT = 6484

Base = declarative_base()
engine = create_engine("sqlite:///:memory:", echo=False)
Session = sessionmaker(bind=engine)
session = Session()


class Peer(Base):
    __tablename__ = "peers"

    id = Column(String(34), primary_key=True)
    addr = Column(String())
    port = Column(Integer)
    last_update = Column(DateTime)


Base.metadata.create_all(engine)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_ADDP, SERVER_PORT))

last_check = 0

while True:

    if last_check < time.time() - 10:
        for peer in session.query(Peer).all():
            if peer.last_update < datetime.now() - timedelta(seconds=50):
                session.query(Peer).filter_by(id=peer.id).delete()
                print(f"Peer {peer.id} deleted")
    packet, addr = sock.recvfrom(65507)
    try:
        packet = packet.decode("utf-8")
    except UnicodeError:
        print(f"Packet from {addr[0]}:{addr[1]} str decode error")
        continue

    try:
        data = json.loads(packet)
    except ValueError:
        print(f"Packet from {addr[0]}:{addr[1]} json decode error")
        continue

    packet_type = data.get("type")
    if packet_type == "annonce":
        peer_id = data.get("id")

        if peer_id is None or peer_id == "":
            print(f"Packet from {addr[0]}:{addr[1]} type {packet_type} id is none")
            continue

        if len(peer_id) != 32:
            print(f"Packet from {addr[0]}:{addr[1]} type {packet_type} len not 32")
            continue

        peer = session.query(Peer).filter_by(id=peer_id).one_or_none()
        if peer is None:
            peer = Peer(id=peer_id, addr=addr[0], port=addr[1], last_update=datetime.now())
            session.add(peer)
            try:
                session.commit()
            except IntegrityError:
                session.reset()
                print(f"Packet from {addr[0]}:{addr[1]} type {packet_type} commit error")
                continue
        else:
            peer.addr = addr[0]
            peer.port = addr[1]
            peer.last_update = datetime.now()
            session.commit()
        packet = json.dumps({"id": peer.id, "addr": peer.addr, "port": peer.port}).encode("utf-8")
        sock.sendto(packet, addr)

    elif packet_type == "get":
        peer_id = data.get("id")

        if peer_id is None or peer_id == "":
            print(f"Packet from {addr[0]}:{addr[1]} type {packet_type} id is none")
            continue

        if len(peer_id) != 32:
            print(f"Packet from {addr[0]}:{addr[1]} type {packet_type} len not 32")
            continue

        peer = session.query(Peer).filter_by(id=peer_id).one_or_none()
        if peer is not None:
            packet = json.dumps({"id": peer.id, "addr": peer.addr, "port": peer.port}).encode("utf-8")
            sock.sendto(packet, addr)
        else:
            print(f"Packet from {addr[0]}:{addr[1]} type {packet_type} peer not fount")
            continue
    else:
        print(f"Packet from {addr[0]}:{addr[1]} unknown type")
        continue

