import config
import sys
import logging
from Modules.router import Router
from Modules.utils import Pipe
import unittest


logging.basicConfig(level=logging.DEBUG, stream=sys.stdout, format=config.LOG_FORMAT)


class TestRouter(unittest.TestCase):
    def __init__(self, methodName: str = "RunTest"):
        super().__init__(methodName)

        self.pipe1, pipe2 = Pipe()

        self.router = Router(pipe2)

        self.route1 = self.router.register_rote(1)
        self.route2 = self.router.register_rote(2)
        self.range_route = self.router.register_range(3, 10)

    def test_sent_to_pipe(self):
        self.pipe1.send((int(1).to_bytes(1) + b"test message", "test"))
        self.pipe1.send(int(1).to_bytes(1) + b"test message")
        self.pipe1.send((int(2).to_bytes(1) + b"tset message", "test"))

        self.pipe1.send((int(11).to_bytes(1) + b"test message", "test"))
        self.pipe1.send((int(3).to_bytes(1) + b"test message", "test"))
        self.pipe1.send((int(5).to_bytes(1) + b"test message", "test"))
        self.pipe1.send((int(10).to_bytes(1) + b"test message", "test"))

        self.assertEqual(self.route1.recv(timeout=1), (b'test message', 'test'))
        self.assertEqual(self.route2.recv(timeout=1), (b'tset message', 'test'))

        self.assertEqual(self.range_route.recv(timeout=1), (b'test message', 'test', 3))
        self.assertEqual(self.range_route.recv(timeout=1), (b'test message', 'test', 5))
        self.assertEqual(self.range_route.recv(timeout=1), (b'test message', 'test', 10))

    def test_recv_from_pipe(self):
        self.route1.send((b"test message", "test"))
        self.route2.send((b"test message", "test"))

        self.range_route.send((b"test message", "test", 0))
        self.range_route.send((b"test message", "test", 3))
        self.range_route.send((b"test message", "test", 5))
        self.range_route.send((b"test message", "test", 10))
        self.range_route.send((b"test message", "test", 11))

        self.assertEqual(self.pipe1.recv(timeout=1), (b'\x01test message', 'test'))
        self.assertEqual(self.pipe1.recv(timeout=1), (b'\x02test message', 'test'))

        self.assertEqual(self.pipe1.recv(timeout=1), (b'\x03test message', 'test'))
        self.assertEqual(self.pipe1.recv(timeout=1), (b'\x05test message', 'test'))
        self.assertEqual(self.pipe1.recv(timeout=1), (b'\ntest message', 'test'))

if __name__ == '__main__':
    unittest.main()