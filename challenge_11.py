# phrasing on the problem description for this one is sort of weird -- I hope I
# understood it correctly

from os import urandom
from random import choice, randint
from typing import Tuple, Callable

from Crypto.Cipher import AES

from challenge_09 import pkcs7


def get_black_box() -> Tuple[str, Callable[[bytes], bytes]]:
    mode = choice(("ECB", "CBC"))

    def black_box(plaintext: bytes) -> bytes:
        key = urandom(16)
        plaintext = pkcs7(urandom(randint(5, 10)) + plaintext + urandom(randint(5, 10)))
        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
        else:
            iv = urandom(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(plaintext)

    return mode, black_box


def detector(func: Callable[[bytes], bytes]) -> str:
    plaintext = b'\x00' * 16 * 4  # four blocks of zero bytes
    ciphertext = func(plaintext)
    if ciphertext[16:32] == ciphertext[32:48]:
        return "ECB"
    else:
        return "CBC"


if __name__ == "__main__":
    for _ in range(17):
        mode, box = get_black_box()
        guess = detector(box)
        print("Actual:", mode, "  Guessed:", guess)
        assert mode == guess
