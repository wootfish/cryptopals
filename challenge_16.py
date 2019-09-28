from os import urandom

from Crypto.Cipher import AES

from challenge_02 import bytes_xor
from challenge_09 import pkcs7, strip_pkcs7


_key = urandom(16)
iv = urandom(16)


def wrap_userdata(data: bytes) -> bytes:
    data = data.translate(None, b';=')
    wrapped = b"comment1=cooking%20MCs;userdata=" + data + b";comment2=%20like%20a%20pound%20of%20bacon"
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7(wrapped))


def check_for_admin(data: bytes, quiet=True) -> bool:
    cipher = AES.new(_key, AES.MODE_CBC, iv)
    plaintext = strip_pkcs7(cipher.decrypt(data))
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
    print("Admin check:", check_for_admin(mal, quiet=False))
