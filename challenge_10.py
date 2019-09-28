import base64

from Crypto.Cipher import AES

from challenge_02 import bytes_xor
from challenge_07 import aes_ecb_decrypt
from challenge_08 import bytes_to_chunks


def aes_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    chunks = bytes_to_chunks(ciphertext, 16)
    prev_ct = iv
    plaintext = b''
    for chunk in chunks:
        plaintext += bytes_xor(aes_ecb_decrypt(key, chunk), prev_ct)
        prev_ct = chunk
    return plaintext


if __name__ == "__main__":
    with open("data/10.txt") as f:
        b64 = f.read()
    ciphertext = base64.b64decode(b64)
    plaintext = aes_cbc_decrypt(b'YELLOW SUBMARINE', ciphertext, b'\x00'*16)

    print(plaintext.decode('ascii'))
