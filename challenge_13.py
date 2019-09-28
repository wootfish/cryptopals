from Crypto.Cipher import AES

from os import urandom
from typing import Dict, Union, Tuple, Sequence

from challenge_09 import pkcs7, strip_pkcs7


key = urandom(16)


def profile_parse(profile: bytes) -> Dict[bytes, bytes]:
    kv_pairs = profile.split(b"&")
    parsed = {
        key: value for key, value in [pair.split(b"=") for pair in kv_pairs]
    }
    return parsed


def profile_build(t: Sequence[Tuple[bytes, bytes]]) -> bytes:
    result = b'&'.join(key + b'=' + val for key, val in t)
    return result


def profile_for(email: bytes) -> bytes:
    # I'm assuming from context here that we aren't meant to do any email
    # validation beyond rejecting profile metacharacters (so like, no RFC 5322)
    email = email.translate(None, b'&=')
    result = profile_build((
        (b'email', email),
        (b'uid', b'10'),
        (b'role', b'user')
        ))
    return result


def enc_profile(email: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    profile = profile_for(email)
    return cipher.encrypt(pkcs7(profile))


def dec_profile(encrypted: bytes) -> Dict[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = strip_pkcs7(cipher.decrypt(encrypted))
    return profile_parse(plaintext)


def do_evil() -> bytes:
    # generate a ciphertext for an admin profile
    ct_1 = enc_profile(b'\x00'*10 + b'admin' + b'\x0b'*11)
    ct_2 = enc_profile(b'eli@sohl.com ')
    return ct_2[:32] + ct_1[16:32]


if __name__ == "__main__":
    evil = do_evil()
    print("Malicious ciphertext:", evil)
    print("Decryption:", dec_profile(evil))
