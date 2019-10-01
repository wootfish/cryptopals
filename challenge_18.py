import struct

from typing import Generator
from base64 import b64decode

from Crypto.Cipher import AES


ciphertext = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")


def keystream(key: bytes, nonce: int = 0, quiet: bool = False) -> Generator[int, None, None]:
    cipher = AES.new(key, AES.MODE_ECB)
    count = 0
    cap = 2**64
    while True:
        plaintext = struct.pack("LL", nonce, count)
        key_block = cipher.encrypt(plaintext)
        yield from key_block
        count = (count + 1) % cap


def aes_ctr_enc(key: bytes, plaintext: bytes, nonce: int = 0) -> bytes:
    return bytes([pt ^ ks for pt, ks in zip(plaintext, keystream(key, nonce))])


aes_ctr_dec = aes_ctr_enc  # lol


if __name__ == "__main__":
    print("Plaintext:", aes_ctr_dec(b'YELLOW SUBMARINE', ciphertext))
