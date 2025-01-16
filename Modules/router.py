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

class FakePipeConnRange(PipeConn):
    def __init__(self, input, output, range):
        super().__init__(input, output)
        self.min, self.max = range

    def send(self, item):
        if type(item) is not tuple:
            logging.debug(f"{self.__class__.__name__} | put - item: {item} type is not tuple")
            raise ValueError
        packet, peer_id, mark = item
        if self.min <= mark <= self.max:
            return self.output.put((int.to_bytes(mark)+packet, peer_id))


class Router:
    def __init__(self, pipe: PipeConn):
        self.pipe = pipe

        self.route = {}

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver, daemon=True)
        self.__receiver_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")

    def register_rote(self, route: int, mark: bool=False) -> FakePipeConn:
        if route > 255:
            logging.debug(f"{self.__class__.__name__} | register_rote - route: {route}, route > 255")
            raise ValueError
        try:
            route = route.to_bytes(1)
        except OverflowError:
            logging.debug(f"{self.__class__.__name__} | register_rote - route: {int.from_bytes(route)}, OverflowError")
            raise ValueError
        input = Queue()
        self.route[route] = (input, mark)
        logging.debug(f"{self.__class__.__name__} | register_rote - add route: {int.from_bytes(route)}")
        return FakePipeConn(input, self.pipe.output, route)

    def register_range(self, min: int, max: int, mark: bool=True) -> FakePipeConnRange:
        if max > 255 and min < max:
            logging.debug(f"{self.__class__.__name__} | register_rote - range: {max}, range > 255")
            raise ValueError
        input = Queue()
        for route in range(min, max+1):
            try:
                route = route.to_bytes(1)
            except OverflowError:
                logging.debug(f"{self.__class__.__name__} | register_rote - route: {int.from_bytes(route)}, OverflowError")
                raise ValueError
            self.route[route] = (input, mark)
        logging.debug(f"{self.__class__.__name__} | register_rote - add range: {min}-{max}")

        return FakePipeConnRange(input, self.pipe.output, (min, max))

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

            output, is_mark = self.route.get(packet[:1])
            if output is None:
                logging.debug(f"{self.__class__.__name__} | Thread receiver - route: {int.from_bytes(packet[:1])} not found, packet drop")
                continue
            if is_mark:
                output.put((packet[1:], peer_id, int.from_bytes(packet[:1])))
            else:
                output.put((packet[1:], peer_id))

        logging.info(f"{self.__class__.__name__} | Thread receiver - stopped")

    def stop(self, join=False):
        self.__is_run = False
        if join:
            self.__receiver_proc.join()
        logging.info(f"{self.__class__.__name__} | Full - stopped")

