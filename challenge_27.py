from os import urandom
from typing import Optional
from string import printable

from Crypto.Cipher import AES

from challenge_02 import bytes_xor
from challenge_09 import pkcs7, strip_pkcs7, PaddingError


_key = urandom(16)


def wrap_userdata(data: bytes) -> bytes:
    data = data.translate(None, b';=')
    wrapped = b"comment1=cooking%20MCs;userdata=" + data + b";comment2=%20like%20a%20pound%20of%20bacon"
    cipher = AES.new(_key, AES.MODE_CBC, _key)
    return cipher.encrypt(pkcs7(wrapped))


def check_pt_ascii(data: bytes) -> Optional[bytes]:
    # returns None if everything's ok
    # if anything outside the ASCII text range is found, returns the plaintext
    cipher = AES.new(_key, AES.MODE_CBC, _key)
    plaintext = cipher.decrypt(data)
    try:
        plaintext = strip_pkcs7(plaintext)
    except PaddingError:
        return plaintext
    for byte in plaintext:
        if byte not in printable.encode('ascii'):
            return plaintext
    return None


def crack():
    ct_original = wrap_userdata(b'\xFF')
    ct_mangled = ct_original[:16] + b'\00'*16 + ct_original[:16]
    result = check_pt_ascii(ct_mangled)  # guaranteed to be error because we made userdata non-ascii
    pt_1 = result[:16]
    pt_3 = result[32:48]
    return bytes_xor(pt_1, pt_3)


if __name__ == "__main__":
    print("Secret key:", _key)
    print("Recovered:", crack())
