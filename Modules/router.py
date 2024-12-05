from queue import Queue
import logging
import threading
from Modules.utils import PipeConn, PipeEmpty


class FakeQueue:
    def __init__(self, route: bytes, output: Queue):
        self.route = route
        self.output = output

    def put(self, item):
        if type(item) != tuple:
            logging.debug(f"{self.__class__.__name__} | put - item: {item} type is not tuple")
            raise ValueError
        return self.output.put((self.route+bytes(item[0]), item[1]))

    def qsize(self) -> int:
        return self.output.qsize()

    def empty(self) -> bool:
        return self.output.empty()


class FakePipeConn(PipeConn):
    def __init__(self, input, output, route):
        super().__init__(input, output)
        self.route = route

    def send(self, item):
        if type(item) is not tuple:
            logging.debug(f"{self.__class__.__name__} | put - item: {item} type is not tuple")
            raise ValueError
        return self.output.put((self.route+bytes(item[0]), item[1]))


class Router:
    def __init__(self, pipe: PipeConn):
        self.pipe = pipe

        self.route = {}

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver, daemon=True)
        self.__receiver_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")

    def register_rote(self, route: int) -> FakePipeConn:
        if route > 255:
            logging.debug(f"{self.__class__.__name__} | register_rote - route: {route}, route > 255")
            raise ValueError
        try:
            route = route.to_bytes(1)
        except OverflowError:
            logging.debug(f"{self.__class__.__name__} | register_rote - route: {route}, OverflowError")
            raise ValueError
        input = Queue()
        self.route[route] = input
        logging.debug(f"{self.__class__.__name__} | register_rote - add route: {route}")
        return FakePipeConn(input, self.pipe.output, route)

    def __receiver(self):
        logging.info(f"{self.__class__.__name__} | Thread receiver - started")
        while self.__is_run:
            try:
                packet, peer_id = self.pipe.recv(timeout=1)
            except PipeEmpty:
                continue
            except ValueError:
                logging.debug(f"{self.__class__.__name__} | Thread receiver - ValueError, packet drop")
                continue

            output = self.route.get(packet[:1])
            if output is None:
                logging.debug(f"{self.__class__.__name__} | Thread receiver - route: {packet[:1]} not found, packet drop")
                continue

            output.put((packet[1:], peer_id))

        logging.info(f"{self.__class__.__name__} | Thread receiver - stopped")

    def stop(self, join=False):
        self.__is_run = False
        if join:
            self.__receiver_proc.join()
        logging.info(f"{self.__class__.__name__} | Full - stopped")

