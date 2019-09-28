from random import randint
from os.path import commonprefix
from os import urandom
from typing import Callable, Tuple
from itertools import count

from Crypto.Cipher import AES

from challenge_09 import pkcs7
from challenge_12 import _secret_postfix


_key = urandom(16)
_secret_prefix_length = randint(1, 34)  # lucky number 34
_secret_prefix = urandom(_secret_prefix_length)


def enc(plaintext: bytes) -> bytes:
    plaintext = pkcs7(_secret_prefix + plaintext + _secret_postfix)
    cipher = AES.new(_key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def find_block_size_and_affix_length(enc: Callable[[bytes], bytes]) -> Tuple[int, int]:
    # we can't tell prefix from postfix here, but we can get their combined
    # length and then determine the prefix length through other means
    l = len(enc(b'A'))
    for i in count(2):
        l2 = len(enc(b'A'*i))
        if l2 > l:
            block_size = l2 - l
            affix_len = l - i
            break
    return block_size, affix_len


def find_prefix_length(enc: Callable[[bytes], bytes], block_size: int) -> int:
    c1 = enc(b'A'*16)
    c2 = enc(b'B'*16)
    ind = block_size * (1 + len(commonprefix((c1, c2))) // block_size)
    for i in range(1, 17):
        c3 = enc(b'A'*i + b'B'*16)
        if c1[:ind] == c3[:ind]:
            return ind - i
    raise Exception("oh no!")  # should be unreachable


if __name__ == "__main__":
    block_size, affix_length = find_block_size_and_affix_length(enc)
    print("Discovered block size:", block_size)
    assert block_size == 16

    prefix_length = find_prefix_length(enc, block_size)
    print("Discovered length for prefix:", prefix_length)
    assert prefix_length == _secret_prefix_length

    postfix_len = affix_length - prefix_length
    print("Discovered length for suffix:", postfix_len)
    assert postfix_len == 138  # value discovered during challenge 12

    prefix_len_to_add = block_size - (prefix_length % block_size)
    prefix_junk_blocks_len = prefix_length + prefix_len_to_add

    print("Prepending", prefix_len_to_add, "bytes to produce",
            prefix_junk_blocks_len, "total bytes of leading garbage")

    # copied over directly from challenge_12
    # (only modifications: mixing in prefix_* variables in a few places)
    blocks_needed = (postfix_len // block_size) + 1
    bytes_needed = block_size*blocks_needed
    slop = block_size - (postfix_len % block_size)
    plaintext = b''

    cutoff_ind = bytes_needed + prefix_junk_blocks_len

    prefix = b'A' * (prefix_len_to_add + bytes_needed)

    while len(prefix) > slop + prefix_len_to_add:
        prefix = prefix[:-1]
        ciphertext = enc(prefix)
        for b in range(256):
            byte = bytes([b])
            candidate = enc(prefix + plaintext + byte)
            if candidate[:cutoff_ind] == ciphertext[:cutoff_ind]:
                plaintext += byte
                break

        # uncomment this line to watch the decryption character-by-character:
        #print(plaintext)

    print("Plaintext:\n")
    print(plaintext.decode("ascii"))
