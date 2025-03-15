from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)

public_key = private_key.public_key()
i = 0
while True:
    message = b"1"*i
    print(len(message))
    ciphertext = public_key.encrypt(
        message,
        padding.PKCS1v15()
    )
    plaintext = private_key.decrypt(
        ciphertext,
        padding.PKCS1v15()
    )

    i+=1
    print(len(ciphertext))

print(message)
print(ciphertext)