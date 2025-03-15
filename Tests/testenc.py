import base64
import os
import threading
import time
import binascii
from queue import Queue

from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC



class InvalidToken(Exception):
    pass



class Symmetric():
    def __init__(self, key: bytes | str) -> None:
        try:
            key = base64.urlsafe_b64decode(key)
        except binascii.Error as exc:
            raise ValueError(
                "Key must be 32 url-safe base64-encoded bytes."
            ) from exc
        if len(key) != 32:
            raise ValueError(
                "Key must be 32 url-safe base64-encoded bytes."
            )

        self._signing_key = key[:16]
        self._encryption_key = key[16:]


    @classmethod
    def generate_key(cls) -> bytes:
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data: bytes) -> bytes:
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, iv)

    def _encrypt_from_parts(self, data: bytes, iv: bytes) -> bytes:

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key),
            modes.CBC(iv),
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
                iv
                + ciphertext
        )

        h = HMAC(self._signing_key, hashes.SHA256())
        h.update(basic_parts)
        hmac = h.finalize()
        return basic_parts + hmac

    def decrypt(self, token: bytes | str) -> bytes:
        return self._decrypt_data(token)


    def _verify_signature(self, data: bytes) -> None:
        h = HMAC(self._signing_key, hashes.SHA256())
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

    def _decrypt_data(self, data: bytes) -> bytes:

        self._verify_signature(data)

        iv = data[:16]
        ciphertext = data[16:-32]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv)
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return unpadded


key = Symmetric.generate_key()

print(key)
f = Symmetric(key)
f2 = Symmetric(key)

def enc(inp, out):
    while True:
        pack = b"A"*mtu
        data = f.encrypt(pack)
        out.put(data)

def dec(inp, out):
    while True:
        pack = inp.get()
        data = f2.decrypt(pack)
        out.put(data)

mtu = 1500

q1, q2 = Queue(), Queue()
q3 = Queue()

for i in range(16):
    threading.Thread(target=enc, args=(q1, q2), daemon=True).start()

for i in range(16):
    threading.Thread(target=dec, args=(q2, q3), daemon=True).start()

packets_size_t = 0
packets_size_d = 0

limit_mb = 1000
limit = limit_mb*1024*1024


timer1 = 0
timer1_u = 1

while True:
    if packets_size_t < limit:
        data = b"A"*mtu

        token = q3.get()
        packets_size_t += len(token)

        #if len(token) > mtu:
        #    break
        #else:
        #    mtu += 1

        #if dataD != data:
        #    raise ValueError("data not valid")

        #else:
            #print("data: ok")

        #print(len(dataD), len(token))
        #print(len(token)-len(dataD))
        #print(base64.urlsafe_b64encode(token))
        #print("_"*5)
    else:
        time.sleep(timer1_u-(time.time()-timer1))

    if time.time()-timer1 > timer1_u:
        print(time.time() - timer1)
        timer1 = time.time()
        print("data speed:", (packets_size_d/1024)/1024, "mb/s")
        print("token speed:", (packets_size_t/1024)/1024, "mb/s")
        print(((packets_size_t-packets_size_d)/1024)/1024, "mb")
        print("_"*5)
        packets_size_t = 0
        packets_size_d = 0