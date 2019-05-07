from challenge_12 import postfix

from random import randint
from os.path import commonprefix
from os import urandom
from typing import Callable
from itertools import count

from Crypto.Cipher import AES

from challenge_09 import pkcs7


key = urandom(16)
prefix_length = randint(1, 34)  # lucky number 34
prefix = urandom(prefix_length)


def enc(plaintext: bytes) -> bytes:
    plaintext = pkcs7(prefix + plaintext + postfix)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def discover_block_size_and_affix_length(enc: Callable[[bytes], bytes]) -> int:
    # can't tell prefix from postfix here but we can get their combined length
    # and then determine the prefix length thru other means
    l = len(enc(b'A'))
    for i in count(2):
        l2 = len(enc(b'A'*i))
        if l2 > l:
            block_size = l2 - l
            affix_len = l - i
            return block_size, affix_len


def discover_prefix_length(enc: Callable[[bytes], bytes], block_size: int) -> int:
    c1 = enc(b'A'*16)
    c2 = enc(b'B'*16)
    ind = block_size * (1 + len(commonprefix((c1, c2))) // block_size)
    for i in range(16):
        c3 = enc(b'A'*i + b'B'*16)
        if c1[:ind] == c3[:ind]:
            return ind - i
    raise Exception("oh no!")  # should be unreachable


if __name__ == "__main__":
    print(prefix_length)
    block_size, affix_length = discover_block_size_and_affix_length(enc)
    print(block_size, affix_length)
    prefix_length = discover_prefix_length(enc, block_size)
    print(prefix_length, affix_length-prefix_length)
