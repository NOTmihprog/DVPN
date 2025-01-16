import logging
import threading
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

    def create_event(self, event: dict):
        self.__event_q.put(event)

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
                    func(event)
                except Exception as e:
                    logging.warning(e)
