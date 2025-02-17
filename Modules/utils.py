import logging
import threading
import msgpack
import socket
import os
from queue import Queue, Empty


class PipeEmpty(Empty):
    pass


class PipeConn:
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
                try:
                    if func.__code__.co_argcount == 1 and func.__code__.co_varnames[0] == "event":
                        func(event)
                    else:
                        try:
                            args = list(event[arg] for arg in func.__code__.co_varnames)
                        except KeyError:
                            continue
                        func(*args)
                except Exception as e:
                    logging.warning(e)

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

