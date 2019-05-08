from random import choice
from os import urandom
from base64 import b64decode
from typing import Optional

from Crypto.Cipher import AES

from challenge_02 import bytes_xor
from challenge_08 import bytes_to_chunks
from challenge_09 import pkcs7, strip_pkcs7, PaddingError


secret_key = b'\xAA' * 16 #urandom(16)
iv = b'\xBB' * 16 #urandom(16)  # known to the attacker


strings = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]


def enc(ind: Optional[int] = None) -> bytes:
    s = choice(strings) if ind is None else strings[ind]
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7(s))


def dec(ciphertext: bytes, iv=iv) -> bytes:
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def padding_oracle(ciphertext: bytes, iv: bytes) -> bool:
    plaintext = dec(ciphertext, iv)
    try:
        strip_pkcs7(plaintext)
    except:
        return False
    return True


def crack_ciphertext_block(block: bytes, iv: bytes) -> bytes:
    # using two prefixes guarantees that our check will run with the byte to
    # the left of the test byte set to two different values; this eliminates
    # the possibility of coincidences like the "02h 02h" example given in the
    # problem statement.

    prefix_1 = b'\x00'
    prefix_2 = b'\x17'  # lucky 17
    plaintext = b''

    for i in range(1, 17):  # even luckier
        postfix = bytes_xor(plaintext, bytes([i]*(i-1)))
        for j in range(256):
            iv_1 = prefix_1*(16-i) + bytes([j]) + postfix
            iv_2 = prefix_2*(16-i) + bytes([j]) + postfix
            #print(dec(block, iv_1).hex(), padding_oracle(block, iv_1))
            if padding_oracle(block, iv_1) and padding_oracle(block, iv_2):
                #print()
                #print("Hit for byte", i, "with IV value", j)
                plaintext = bytes([j^i]) + plaintext
                #print("Partial plaintext:", plaintext)
                break
        else:
            print("No match found for byte", i)
            #print("Plaintexts from last attempt:")
            #print(dec(block, iv_1).hex())
            #print(dec(block, iv_2).hex())
            raise Exception("oh no!")  # no matching byte found (?!)

    return bytes_xor(plaintext, iv)


def cbc_oracle_attack(ciphertext: bytes) -> bytes:
    #print("Ciphertext:", ciphertext.hex())

    plaintext = b''
    block_iv = iv

    blocks = bytes_to_chunks(ciphertext, 16)
    for block in blocks:  # skip iv block
        #print("Attacking block", block.hex())
        plaintext += crack_ciphertext_block(block, block_iv)
        block_iv = block  # this block is effectively the next block's iv

    return strip_pkcs7(plaintext)


if __name__ == "__main__":
    for i in range(len(strings)):
        ciphertext = enc(i)
        plaintext = cbc_oracle_attack(ciphertext)
        assert plaintext == strings[i]
        print(b64decode(plaintext).decode('ascii'))
