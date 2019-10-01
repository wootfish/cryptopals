from itertools import count
from base64 import b64decode
from typing import Callable, Tuple
from os import urandom

from Crypto.Cipher import AES

from challenge_09 import pkcs7
from challenge_11 import detector


_secret_postfix = b64decode("""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
""")

_key = urandom(16)


def enc(plaintext: bytes) -> bytes:
    plaintext = pkcs7(plaintext + _secret_postfix)
    cipher = AES.new(_key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def find_block_size_and_postfix_length(enc: Callable[[bytes], bytes]) -> Tuple[int, int]:
    # we need to know the postfix length to have a clean termination condition
    # for the decryption loop, but taking len(postfix) feels like cheating, so
    # this function just figures it out in tandem w/ finding the block size
    l = len(enc(b'A'))
    for i in count(2):
        l2 = len(enc(b'A'*i))
        if l2 > l:
            block_size = l2 - l
            postfix_len = l - i
            break
    return block_size, postfix_len


if __name__ == "__main__":
    block_size, postfix_len = find_block_size_and_postfix_length(enc)
    assert block_size == 16

    mode = detector(enc)
    assert mode == "ECB"

    print("Postfix length determined to be", postfix_len)
    blocks_needed = (postfix_len // block_size) + 1
    bytes_needed = block_size * blocks_needed
    slop = block_size - (postfix_len % block_size)
    plaintext = b''

    prefix = b'A' * bytes_needed

    while len(prefix) > slop:
        prefix = prefix[:-1]
        ciphertext = enc(prefix)
        for b in range(256):
            byte = bytes([b])
            candidate = enc(prefix + plaintext + byte)
            if candidate[:bytes_needed] == ciphertext[:bytes_needed]:
                plaintext += byte
                break

        # uncomment this line to watch the decryption character-by-character:
        #print(plaintext)

    print("Plaintext:\n")
    print(plaintext.decode("ascii"))
