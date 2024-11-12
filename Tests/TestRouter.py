import config
import sys
import logging
from Modules.router import Router


logging.basicConfig(level=config.LOG_LEVEL, stream=sys.stdout, format=config.LOG_FORMAT)

router = Router()

test = router.register_rote(b"test")
tset = router.register_rote(b"tset")

router.input.put((b"testtest message", "test"))
router.input.put(b"testtest message")
router.input.put((b"tsettest message", "test"))

print("test:", test[0].get(timeout=1))
print("tset:", tset[0].get(timeout=1))

test[1].put((b"test message", "test"))
tset[1].put((b"test message", "test"))

print(router.output.get(timeout=1))
print(router.output.get(timeout=1))

router.stop()
