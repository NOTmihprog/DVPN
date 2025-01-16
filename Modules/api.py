import threading
import socket
import os
import logging
import msgpack
import time

from Modules.router import FakePipeConnRange
from Modules.utils import PipeEmpty


class Connector:
    def __init__(self, sock):
        self.sock = sock
        self.sock.setblocking(True)
        self.__is_run = True

    def close(self):
        self.sock.close()

    def recv(self):
        try:
            packet, addr = self.sock.recvfrom(65507)
        except BlockingIOError:
            logging.info(f"{self.__class__.__name__} | BlockingIOError")
            return None, None
        except TimeoutError:
            return None, None
        except OSError:
            logging.info(f"{self.__class__.__name__} | OSError")
            return None, None
        try:
            return msgpack.loads(packet), addr
        except msgpack.ExtraData:
            logging.info(f"{self.__class__.__name__} | msgpack ExtraData")
            return None, None
        except msgpack.FormatError:
            logging.info(f"{self.__class__.__name__} | msgpack FormatError")
            return None, None
        except msgpack.StackError:
            logging.info(f"{self.__class__.__name__} | msgpack StackError")
            return None, None
        except ValueError:
            logging.info(f"{self.__class__.__name__} | msgpack ValueError")
            return None, None


    def send(self, packet, addr):
        try:
            self.sock.sendto(msgpack.dumps(packet), addr)
        except PermissionError:
            logging.info(f"{self.__class__.__name__} | PermissionError")
            return None
        except OSError:
            logging.info(f"{self.__class__.__name__} | OSError")
            return None


class ConnectorInet(Connector):
    def __init__(self, bind_addr: tuple[str, int]):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__sock.bind(bind_addr)

        super().__init__(self.__sock)


class ConnectorUnix(Connector):
    def __init__(self, bind_addr: str):
        if os.path.exists(bind_addr):
            os.remove(bind_addr)
        self.__sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.__sock.bind(bind_addr)

        super().__init__(self.__sock)


class API:
    def __init__(self, connector: Connector, uapi, routes_pipe):
        self.uapi = uapi
        self.con = connector

        self.connections = {}
        self.conn_ping = {}
        self.conn_ping_send_time = {}
        self.conn_ping_receive_time = {}
        self.conn_ping_packets_send = {}

        self.router = APIRouter(self, routes_pipe)

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver, daemon=True)
        self.__ping_sender_proc = threading.Thread(target=self.__ping_sender, daemon=True)

        self.__receiver_proc.start()
        self.__ping_sender_proc.start()

        logging.info(f"{self.__class__.__name__} | Full - started")

    def __send_close(self, conn):
        self.con.send({"type": "close"}, conn)

    def close_conn(self, conn):
        del self.connections[conn]
        self.conn_ping[conn] = None
        self.conn_ping_send_time[conn] = None
        self.conn_ping_receive_time[conn] = None
        self.conn_ping_packets_send[conn] = None
        self.__send_close(conn)
        self.router.del_routes_at_addr(conn)
        logging.debug(f"{self.__class__.__name__} | conn {conn} closed")

    def __handler_get(self, packet):
        request = packet.get("req")
        peer_id = packet.get("peer_id")
        if request == "peers":
            return self.uapi.get_peers()

        elif request == "peer_name":
            return self.uapi.get_peer_name(peer_id)

        elif request == "peer_addr":
            return self.uapi.get_peer_addr(peer_id)

        elif request == "peer_crypto":
            return self.uapi.get_peer_crypto(peer_id)

        elif request == "peer_sub_args":
            return self.uapi.get_peer_sub_args(peer_id)

        elif request == "peer_sub_arg":
            return self.uapi.get_peer_sub_arg(peer_id, packet.get("arg"))

        elif request == "peer_endpoint":
            return self.uapi.get_endpoint(peer_id)

        elif request == "peer_status":
            return self.uapi.get_peer_status(peer_id)

        elif request == "peer_ping":
            return self.uapi.get_peer_ping(peer_id)

        elif request == "peer_crypto_status":
            return self.uapi.get_crypto_status(peer_id)

        elif request == "server_status":
            return self.uapi.get_server_status()

        elif request == "local_addr":
            return self.uapi.get_local_addr()


    def __send_event(self, event, addr):
        self.con.send({"type": "event", "event": event}, addr)
        logging.debug(f"{self.__class__.__name__} | send event to conn {addr}")

    def event_handler(self, event):
        for conn in self.connections.copy():
            self.__send_event(event, conn)

    def __handler_route(self, packet, addr):
        request = packet.get("req")
        route = packet.get("route")
        if type(route) is not int:
            return "not_int"

        if request == "reg":
            return self.router.add_route(addr, route)

        elif request == "del":
            if self.router.ROUTE2ADDR.get(route) != addr:
                return "not_permission"
            return self.router.del_route(route)

        elif request == "routes":
            return self.router.get_routes(addr)

    def __receiver(self):
        while self.__is_run:
            packet, addr = self.con.recv()

            if type(packet) is not dict:
                continue
            packet_type = packet.get("type")
            if packet_type == "init":
                self.connections[addr] = {"name": packet.get("name")}

            elif packet_type == "ping":
                self.con.send({"type": "pong"}, addr)
                logging.debug(f"{self.__class__.__name__} | receive ping from conn {addr}")


            elif self.connections.get(addr) is None: #  position is elif not an error
                self.__send_close(addr)
                logging.debug(f"{self.__class__.__name__} | receive {packet_type} from unknown conn {addr}")
                continue

            elif packet_type == "net":
                self.router.packet_handler(packet, addr)


            elif packet_type == "pong":
                send_time = self.conn_ping_send_time.get(addr)
                if send_time is None:
                    continue
                receive_time = time.time_ns()
                ping = (receive_time - send_time) / 1000000
                self.conn_ping[addr] = ping
                self.conn_ping_receive_time[addr] = receive_time
                logging.debug(f"{self.__class__.__name__} | receive pong from conn {addr} ping: {ping}")

            elif packet_type == "get":
                response = self.__handler_get(packet)
                self.con.send({"type": "res",
                                      "id": packet.get("id"),
                                      "res": response}, addr)

            elif packet_type == "route":
                response = self.__handler_route(packet, addr)
                self.con.send({"type": "res",
                                      "id": packet.get("id"),
                                      "res": response}, addr)

            elif packet_type == "close":
                self.close_conn(addr)

    def __ping_sender(self):
        logging.info(f"{self.__class__.__name__} | Thread ping sender - started")
        while self.__is_run:
            for conn in self.connections.copy():
                ping_packets = self.conn_ping_packets_send.get(conn)
                if ping_packets is None:
                    ping_packets = 0

                last_recv_time = self.conn_ping_receive_time.get(conn)
                if last_recv_time is None:
                    last_recv_time = 0

                if ping_packets > 3 and (time.time_ns() - last_recv_time) / 1000000000 > 45:
                    self.close_conn(conn)
                    continue

                self.con.send({"type": "ping"}, conn)
                self.conn_ping_send_time[conn] = time.time_ns()
                self.conn_ping_packets_send[conn] = ping_packets + 1

                logging.debug(f"{self.__class__.__name__} | send ping to conn {conn}")
            time.sleep(15)
        logging.info(f"{self.__class__.__name__} | Thread ping sender - stopped")


    def stop(self, join=False):
        self.__is_run = False
        self.router.stop(join)
        if join:
            self.__receiver_proc.join()
            self.__ping_sender_proc.join()

        logging.info(f"{self.__class__.__name__} | Full - stopped")


class APIRouter:
    def __init__(self, api: API, range_pipe: FakePipeConnRange):
        self.api = api
        self.range_pipe = range_pipe

        self.ADDR2ROUTES = {}
        self.ROUTE2ADDR = {}

        self.__is_run = True
        self.__sender_proc = threading.Thread(target=self.__sender, daemon=True)

        self.__sender_proc.start()

        logging.info(f"{self.__class__.__name__} | Full - started")

    def add_route(self, addr, route: int):
        if self.ROUTE2ADDR.get(route) is not None:
            logging.debug(f"{self.__class__.__name__} | add_route - conn {addr} route exist")
            return "route_exist"
        if not (self.range_pipe.min <= route <= self.range_pipe.max):
            logging.debug(f"{self.__class__.__name__} | add_route - conn {addr}"
                          f" out of range {self.range_pipe.min}-{self.range_pipe.max}")
            return "out_of_range"

        self.ROUTE2ADDR[route] = addr
        if type(self.ADDR2ROUTES.get(addr)) is not list:
            self.ADDR2ROUTES[addr] = [route,]
        else:
            self.ADDR2ROUTES[addr].append(route)
        logging.debug(f"{self.__class__.__name__} | add_route - conn {addr} route {route} added")

    def del_route(self, route: int):
        addr = self.ROUTE2ADDR.get(route)
        if addr is None:
            logging.debug(f"{self.__class__.__name__} | del_route - conn {addr} route not exist")
            return "route_not_exist"

        try:
            self.ADDR2ROUTES[addr].remove(route)
        except ValueError:
            logging.debug(f"{self.__class__.__name__} | del_route - conn {addr} route {route} ValueError")
        except KeyError:
            logging.debug(f"{self.__class__.__name__} | del_route - conn {addr} route {route} ADDR2ROUTES KeyError")

        try:
            del self.ROUTE2ADDR[route]
        except KeyError:
            logging.debug(f"{self.__class__.__name__} | del_route - conn {addr} route {route} ROUTE2ADDR KeyError")
        logging.debug(f"{self.__class__.__name__} | add_route - conn {addr} route {route} deleted")

    def del_routes_at_addr(self, addr):
        routes = self.ADDR2ROUTES.get(addr)
        if routes is None:
            logging.debug(f"{self.__class__.__name__} | del_routes_at_addr - conn {addr} routes not exist")
            return "routes_not_exist"
        for route in routes:
            self.del_route(route)
        logging.debug(f"{self.__class__.__name__} | del_routes_at_addr - conn {addr} all routes deleted")

    def get_routes(self, addr):
        routes = self.ADDR2ROUTES.get(addr)
        return routes if routes is not None else list()

    def packet_handler(self, packet, addr):
        route = packet.get("rou")
        packet_data = packet.get("pack")
        peer_id = packet.get("peer_id")
        if route is None or packet_data is None or peer_id is None or self.ROUTE2ADDR.get(route) != addr:
            logging.debug(f"{self.__class__.__name__} | packet_handler - conn {addr} drop packet to {peer_id}")
            return None
        self.range_pipe.send((packet_data, peer_id, route))

    def __sender(self):
        logging.info(f"{self.__class__.__name__} | Thread sender - started")
        while self.__is_run:
            try:
                packet, peer_id, route = self.range_pipe.recv(timeout=1)
            except PipeEmpty:
                continue
            except ValueError:
                logging.debug(f"{self.__class__.__name__} | Thread sender - ValueError, packet drop")
                continue
            addr = self.ROUTE2ADDR.get(route)
            if addr is None:
                logging.debug(f"{self.__class__.__name__} | Thread sender - packet drop, peer_id {peer_id}")
                continue
            self.api.con.send({"type": "net", "rou": route, "pack": packet, "peer_id": peer_id}, addr)


    def stop(self, join=False):
        self.__is_run = False
        if join:
            self.__sender_proc.join()