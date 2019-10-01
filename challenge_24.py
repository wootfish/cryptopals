from challenge_21 import MT19937

from os import urandom
from math import ceil
from time import time
from typing import Optional


"""
Phrasing on this one is sort of hard to interpret. Hope I got the idea right.
The common theme seems to be exploiting low key entropy.
"""


message = b'deltron, tremendous force to end your course'


def mt_cipher(key: int, plaintext: bytes, r: Optional[MT19937] = None) -> bytes:
    r = r or MT19937()
    r.seed(key)
    ciphertext = b''

    # each MT output is good for 4 bytes of keystream
    keystream = [r.extract_number() for _ in range(ceil(len(plaintext)/4))]
    for i, ch in enumerate(plaintext):
        ks_n = keystream[i//4]
        ks_b = (ks_n >> 4 * (i % 4)) & 0xFF
        ciphertext += bytes([ks_b ^ ch])

    return ciphertext


def get_ciphertext(message: bytes) -> bytes:
    secret_key = int.from_bytes(urandom(2), 'big')
    plaintext = urandom(int.from_bytes(urandom(1), 'big')) + message
    ciphertext = mt_cipher(secret_key, plaintext)
    return ciphertext


def get_token() -> bytes:
    return mt_cipher(int(time()), message)


def check_token(token: bytes, quiet=False) -> bool:
    r = MT19937()
    t_curr = int(time())
    for t in range(t_curr, t_curr - (60*60*6), -1):
        candidate = mt_cipher(t, token, r)
        if candidate == message:
            if not quiet: print("confirmed token was keyed from timestamp", t)
            return True
    else:
        return False


if __name__ == "__main__":
    ciphertext = get_ciphertext(message)

    # a 16 bit key is absolutely tiny. might as well just use exhaustive search
    r = MT19937()
    for b in range(2**16):
        if (b % 1024 == 0): print(".", end="", flush=True)
        candidate = mt_cipher(b, ciphertext, r)
        if message in candidate:
            print("found key", b)
            break
    else:
        raise Exception("oh no!")  # key not found

    token = get_token()
    print("Token check results:", check_token(token))
