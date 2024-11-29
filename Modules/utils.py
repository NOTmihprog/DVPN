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
    def __new__(cls):
        q1 = Queue()
        q2 = Queue()
        return PipeConn(input=q1, output=q2), PipeConn(input=q2, output=q1)

