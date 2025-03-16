import logging
import threading
import msgpack
import socket
import os
import re
from queue import Queue, Empty
from colorama import Fore


class PipeEmpty(Empty):
    pass


class PipeConn:
    __slots__ = ("input", "output")
    def __init__(self, input: Queue, output: Queue):
        self.input = input
        self.output = output

    def recv(self, timeout: float = None):
        try:
            return self.input.get(timeout=timeout)
        except Empty:
            raise PipeEmpty

    def send(self, item):
        return self.output.put(item)


class Pipe:
    def __new__(cls, maxsize=0):
        q1 = Queue(maxsize=maxsize)
        q2 = Queue(maxsize=maxsize)
        return PipeConn(input=q1, output=q2), PipeConn(input=q2, output=q1)


class EventPipe(threading.Thread):
    __slots__ = ("__event_q", "__func_list")
    def __init__(self, maxsize=0):
        super().__init__()
        self.__event_q = Queue(maxsize=maxsize)
        self.__func_list = []

        self.daemon = True
        self.start()

    def event(self, **kwargs):
        self.__event_q.put(kwargs)

    def add_listener(self, func):
        self.__func_list.append(func)
        return func

    def del_listener(self, func):
        self.__func_list.remove(func)

    def run(self):
        while True:
            event = self.__event_q.get()
            for func in self.__func_list:

                func_args = list(func.__code__.co_varnames[:func.__code__.co_argcount])
                if len(func_args) > 0 and func_args[0] == "self":
                    func_args.remove("self")
                try:
                    if len(func_args) == 1 and func_args[0] == "event":
                        func(event)
                    else:
                        try:
                            args = list(event[arg] for arg in func_args)
                        except KeyError:
                            continue
                        func(*args)
                except Exception as e:
                    logging.warning(e)

class Connector:
    __slots__ = ("sock", "__is_run")
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
    __slots__ = ("__sock",)
    def __init__(self, bind_addr: tuple[str, int]):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__sock.bind(bind_addr)

        super().__init__(self.__sock)


class ConnectorUnix(Connector):
    __slots__ = ("__sock",)
    def __init__(self, bind_addr: str):
        if os.path.exists(bind_addr):
            os.remove(bind_addr)
        self.__sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.__sock.bind(bind_addr)

        super().__init__(self.__sock)



class PeerLogsHandler(logging.Handler):
    __slots__ = ("__peer_storage", "_logs_pipe", "peer_id_mask", "ip_mask")
    def __init__(self, peer_storage, level: int | str = 0):
        super().__init__(level)
        self.__peer_storage = peer_storage
        self._logs_pipe = EventPipe()
        self._logs_pipe.add_listener(self.__log_handler)
        self.peer_id_mask = re.compile("[a-f0-9]{32}")
        self.ip_mask = re.compile("(\\b25[0-5]|\\b2[0-4][0-9]|\\b[01]?[0-9][0-9]?)"
                                  "(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}")

    def peer_format(self, peer_id: str):
        return (f"{Fore.LIGHTYELLOW_EX}{self.__peer_storage.get_peer_name(peer_id)}"
                f"{Fore.GREEN}({Fore.LIGHTBLACK_EX}{peer_id}{Fore.GREEN}){Fore.LIGHTWHITE_EX}")

    @staticmethod
    def ip_format(ip: str):
        return Fore.WHITE + (f"{Fore.GREEN}.{Fore.WHITE}".join(ip.split("."))) + Fore.LIGHTWHITE_EX

    def __log_handler(self, log):
        res = self.peer_id_mask.search(log)
        if res is not None:
            peer_id = res.group(0)
            log = log.replace(peer_id, self.peer_format(peer_id))

        res = self.ip_mask.search(log)
        if res is not None:
            ip = res.group(0)
            log = log.replace(ip, self.ip_format(ip))

        print(log)

    def emit(self, record):
        log_entry = self.format(record)
        self._logs_pipe.event(log=log_entry)
