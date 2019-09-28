from os import urandom

from challenge_02 import bytes_xor
from challenge_09 import pkcs7, strip_pkcs7
from challenge_18 import aes_ctr_enc
from challenge_18 import aes_ctr_dec


_key = urandom(16)
_iv = urandom(16)


def wrap_userdata(data: bytes) -> bytes:
    data = data.translate(None, b';=')  # "sanitize" the input by removing ;= strings (not strictly necessary but hey)
    wrapped = b"comment1=cooking%20MCs;userdata=" + data + b";comment2=%20like%20a%20pound%20of%20bacon"
    return aes_ctr_enc(_key, pkcs7(wrapped))


def check_for_admin(data: bytes, quiet=True) -> bool:
    plaintext = strip_pkcs7(aes_ctr_dec(_key, data))
    if not quiet: print("Decrypted data string:", plaintext)
    return b';admin=true;' in plaintext


def make_admin() -> bytes:
    a_block = b'A'*16
    flipper = bytes_xor(a_block, b';admin=true;foo=')
    ciphertext = wrap_userdata(a_block*4)
    to_xor = b'\x00'*48 + flipper
    modified = bytes_xor(ciphertext, to_xor.ljust(len(ciphertext), b'\x00'))
    return modified


if __name__ == "__main__":
    mal = make_admin()
    print("Malicious ciphertext:", mal)
    check = check_for_admin(mal, quiet=False)
    print("Admin check:", check)
