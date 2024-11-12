from queue import Queue, Empty
import logging
import threading


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


class Router:
    def __init__(self, input=None, output=None):
        if input is None:
            self.input = Queue()
        else:
            self.input = input
        if output is None:
            self.output = Queue()
        else:
            self.output = output

        self.route = {}

        self.__is_run = True
        self.__receiver_proc = threading.Thread(target=self.__receiver)
        self.__receiver_proc.start()
        logging.info(f"{self.__class__.__name__} | Full - started")

    def register_rote(self, route: bytes) -> (Queue, FakeQueue):
        route = bytes(route)
        if len(route) != 4:
            logging.debug(f"{self.__class__.__name__} | register_rote - route: {route}, len != 4")
            raise ValueError
        input = Queue()
        self.route[route] = input
        logging.debug(f"{self.__class__.__name__} | register_rote - add route: {route}")
        return input, FakeQueue(route, self.output)

    def __receiver(self):
        logging.info(f"{self.__class__.__name__} | Thread receiver - started")
        while self.__is_run:
            try:
                packet, peer_id = self.input.get(timeout=1)
            except Empty:
                continue
            except ValueError:
                logging.debug(f"{self.__class__.__name__} | Thread receiver - ValueError, packet drop")
                continue

            output = self.route.get(packet[:4])
            if output is None:
                logging.debug(f"{self.__class__.__name__} | Thread receiver - route not found, packet drop")
                continue

            output.put((packet[4:], peer_id))

        logging.info(f"{self.__class__.__name__} | Thread receiver - stopped")

    def stop(self, join=False):
        self.__is_run = False
        if join:
            self.__receiver_proc.join()
        logging.info(f"{self.__class__.__name__} | Full - stopped")

