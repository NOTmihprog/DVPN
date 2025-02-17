import config
import sys
import logging
from Modules.peer_storage import PeerConfigStorage
import unittest


logging.basicConfig(level=logging.DEBUG, stream=sys.stdout, format=config.LOG_FORMAT)

"""            
class TestConfigStorage(unittest.TestCase):
    def __init__(self, methodName: str = "RunTest"):
        super().__init__(methodName)

        self.peer_storage = PeerConfigStorage("./test-peer.cnf")


    def test_write_and_read_config(self):
        self.peer_storage.set_peer(peer_id="test", name="test", addr="192.168.2.1")
        self.assertEqual(self.peer_storage.get_peer("test"), {'peer_id': 'test', 'name': 'test', 'addr': '192.168.2.1', 'crypto': None, 'sub_args': None})
"""

def event_test(event):
    print("event", event)


if __name__ == '__main__':
    t = peer_storage = PeerConfigStorage("./test-peer.cnf")
    t.add_listener(event_test)
    t.set_peer(peer_id="test", name="tests", addr="192.168.2.1", sub_args={"test": "test"})
    t.set_peer(peer_id="test", name="test", addr="192.168.2.1")
    t.set_peer(peer_id="test", name="tes", addr="192.168.2.1", force=True)
    t.set_peer_sub_arg("test", "test", 123)
    print(t.get_peer_sub_arg("test", "test"))
    print(t.get_peer("test"))
    print(t.get_peers())
    t.del_peer("test")
    print(t.get_peer("test"))
    #unittest.main()