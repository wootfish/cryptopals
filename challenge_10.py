from Crypto.Cipher import AES

from challenge_2 import bytes_xor
from challenge_7 import aes_ecb_decrypt
from challenge_8 import bytes_to_chunks


def aes_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes):
    chunks = bytes_to_chunks(ciphertext, 16)
    prev_ct = iv
    plaintext = b''
    for chunk in chunks:
        plaintext += bytes_xor(aes_ecb_decrypt(key, chunk), prev_ct)
        prev_ct = chunk
    return plaintext


if __name__ == "__main__":
    import sys
    import base64
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 challenge_10.py filename")

    with open(sys.argv[1]) as f:
        b64 = f.read()
    ciphertext = base64.b64decode(b64)
    plaintext = aes_cbc_decrypt(b'YELLOW SUBMARINE', ciphertext, b'\x00'*16)

    print(plaintext.decode('ascii'))
