import time
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

