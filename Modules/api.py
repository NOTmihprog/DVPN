__author__ = "mihprog"

__license__ = "GPL"
__version__ = "2.0.0"

__email__ = "mih@mihprog.com"
__status__ = "Production"

import ipaddress
import threading
import logging
import time

from Modules.router import FakePipeConnRange
from Modules.utils import PipeEmpty, Connector, PeerId
from Modules.peer_storage import PeerConfigStorage


class API:
    __slots__ = ("uapi", "__peer_storage", "con", "connections", "conn_ping", "conn_ping_send_time",
                 "conn_ping_receive_time", "conn_ping_packets_send", "router", "__is_run", "__receiver_proc",
                 "__ping_sender_proc")
    def __init__(self, connector: Connector, uapi, peer_storage: PeerConfigStorage, routes_pipe):
        self.uapi = uapi
        self.__peer_storage = peer_storage
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

        self.__peer_storage.add_listener(self.event_handler)

        bind_addr = self.con.get_bind()
        if type(bind_addr) is tuple:
            bind_addr = f"{bind_addr[0]}:{bind_addr[1]}"

        logging.info(f"{self.__class__.__name__} | Listen address: {bind_addr}")

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
        addr = packet.get("addr")
        if addr is not None:
            addr = (addr[0], addr[1])
        match request:
            case "peer_id":
                return self.__peer_storage.peer_id

            case "peers":
                return self.__peer_storage.get_peers_id()

            case "peer_exist":
                return self.__peer_storage.peer_exists(peer_id)

            case "peer_name":
                return self.__peer_storage.get_peer_name(peer_id)

            case "peer_addr":
                return self.__peer_storage.get_peer_addr(peer_id)

            case "peer_crypto":
                return self.__peer_storage.get_peer_crypto(peer_id)

            case "peer_sub_args":
                return self.__peer_storage.get_peer_sub_args(peer_id)

            case "peer_sub_arg":
                return self.__peer_storage.get_peer_sub_arg(peer_id, packet.get("arg"))

            case "peer_endpoint":
                return self.__peer_storage.get_peer_endpoint(peer_id)

            case "peer_status":
                return self.uapi.get_peer_status(peer_id)

            case "peer_ping":
                return self.uapi.get_peer_ping(peer_id)

            case "peer_crypto_status":
                return self.uapi.get_crypto_status(peer_id)

            case "servers":
                return self.uapi.get_servers()

            case "server_status":
                return self.uapi.get_server_status(addr)

            case "server_key":
                return self.uapi.get_server_key(addr)

            case "server_last_announce":
                return self.uapi.get_server_last_announce(addr)

            case "server_last_search":
                return self.uapi.get_server_last_search(addr)

            case "server_last_response":
                return self.uapi.get_server_last_response(addr)

            case "local_addr":
                return self.uapi.get_local_addr()

    def __handler_set(self, packet):
        request = packet.get("req")
        match request:
            case "peer":
                peer_id = packet.get("peer_id")
                try:
                    PeerId.validate(peer_id)
                except ValueError:
                    return "peer_id_validate_error"

                name = packet.get("name")
                if name is not None and type(name) is not str:
                    return "name_not_str"

                addr = packet.get("addr")
                try:
                    ipaddress.IPv4Address(addr)
                except ValueError:
                    return "addr_validate_error"
                endpoint = packet.get("endpoint")
                if type(endpoint) is not list:
                    return "endpoint_not_list"
                if len(endpoint) < 2:
                    return "endpoint_len_not_2"
                if type(endpoint[0]) is not str:
                    return "endpoint_addr_not_str"
                if type(endpoint[1]) is not int:
                    return "endpoint_port_not_int"
                endpoint = (endpoint[0], endpoint[1])

                crypto = packet.get("crypto")
                if crypto is not None and type(crypto) is not dict:
                    return "crypto_not_dict"

                sub_args = packet.get("sub_args")
                if sub_args is not None and type(sub_args) is not dict:
                    return "sub_args_not_dict"

                force = packet.get("force")
                if force is None:
                    force = False
                elif type(force) is not bool:
                    return "force_not_bool"

                return self.__peer_storage.set_peer(peer_id, name=name, addr=addr, endpoint=endpoint, crypto=crypto,
                                                    sub_args=sub_args, force=force)

    def __handler_del(self, packet):
        request = packet.get("req")

        peer_id = packet.get("peer_id")
        try:
            PeerId.validate(peer_id)
        except ValueError:
            return "peer_id_validate_error"

        if not self.__peer_storage.peer_exists(peer_id):
            return "peer_not_exist"
        match request:
            case "peer":
                if self.__peer_storage.peer_is_self(peer_id):
                    return "error_delete_self_peer"
                return self.__peer_storage.del_peer(peer_id)

            case "peer_endpoint":
                return self.__peer_storage.del_peer_endpoint(peer_id)

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

        match request:
            case "reg":
                return self.router.add_route(addr, route)

            case "del":
                if self.router.ROUTE2ADDR.get(route) != addr:
                    return "not_permission"
                return self.router.del_route(route)

            case "routes":
                return self.router.get_routes(addr)

    def __receiver(self):
        while self.__is_run:
            try:
                packet, addr = self.con.recv()

                if type(packet) is not dict:
                    continue
                packet_type = packet.get("type")
                conn_inited = self.connections.get(addr) is not None
                match conn_inited, packet_type:
                    case False, "init":
                        self.connections[addr] = {"name": packet.get("name")}

                    case _, "ping":
                        self.con.send({"type": "pong"}, addr)
                        logging.debug(f"{self.__class__.__name__} | receive ping from conn {addr}")


                    case False, _: #  position is case not an error
                        self.__send_close(addr)
                        logging.debug(f"{self.__class__.__name__} | receive {packet_type} from unknown conn {addr}")
                        continue

                    case True, "net":
                        self.router.packet_handler(packet, addr)

                    case True, "pong":
                        send_time = self.conn_ping_send_time.get(addr)
                        if send_time is None:
                            continue
                        receive_time = time.time_ns()
                        ping = (receive_time - send_time) / 1000000
                        self.conn_ping[addr] = ping
                        self.conn_ping_receive_time[addr] = receive_time
                        logging.debug(f"{self.__class__.__name__} | receive pong from conn {addr} ping: {ping}")

                    case True, "get":
                        response = self.__handler_get(packet)
                        self.con.send({"type": "res",
                                              "id": packet.get("id"),
                                              "res": response}, addr)

                    case True, "set":
                        response = self.__handler_set(packet)
                        self.con.send({"type": "res",
                                       "id": packet.get("id"),
                                       "res": response}, addr)

                    case True, "del":
                        response = self.__handler_del(packet)
                        self.con.send({"type": "res",
                                       "id": packet.get("id"),
                                       "res": response}, addr)

                    case True, "route":
                        response = self.__handler_route(packet, addr)
                        self.con.send({"type": "res",
                                              "id": packet.get("id"),
                                              "res": response}, addr)

                    case True, "close":
                        self.close_conn(addr)

            except Exception as e:
                logging.error(f"{self.__class__.__name__} | Runtime error: {e}")

    def __ping_sender(self):
        logging.info(f"{self.__class__.__name__} | Thread ping sender - started")
        while self.__is_run:
            try:
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

            except Exception as e:
                logging.error(f"{self.__class__.__name__} | Runtime error: {e}")
        logging.info(f"{self.__class__.__name__} | Thread ping sender - stopped")


    def stop(self, join=False):
        self.__is_run = False
        self.router.stop(join)
        if join:
            self.__receiver_proc.join()
            self.__ping_sender_proc.join()

        logging.info(f"{self.__class__.__name__} | Full - stopped")


class APIRouter:
    __slots__ = ("api", "range_pipe", "ADDR2ROUTES", "ROUTE2ADDR", "__is_run", "__sender_proc")
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