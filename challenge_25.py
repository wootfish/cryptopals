from os import urandom
from base64 import b64decode

from challenge_02 import bytes_xor
from challenge_07 import aes_ecb_decrypt as aes_ecb_dec
from challenge_08 import bytes_to_chunks
from challenge_09 import strip_pkcs7
from challenge_18 import aes_ctr_enc


_key = urandom(16)


def _edit(ciphertext: bytes, key: bytes, offset: int, newtext: bytes) -> bytes:
    """
    Returns the full ciphertext with the specified edit performed. This isn't
    "optimized" to take advantage of CTR's random-access feature because I just
    figured, hey, it runs fast enough already.
    """
    start = offset
    end = start + len(newtext)
    pt_original = aes_ecb_dec(key, ciphertext)
    pt_modified = pt_original[:start] + newtext + pt_original[end:]
    ct_new = aes_ctr_enc(_key, pt_modified)
    return ct_new


def edit(offset: int, newtext: bytes) -> bytes:
    """
    Version of _edit that is API-exposed to attacker
    """
    return _edit(ciphertext, _key, offset, newtext)


def crack():
    ct_blocks = bytes_to_chunks(ciphertext, 16)
    plaintext = b''
    for i, ct_block in enumerate(ct_blocks):
        ct2 = edit(16*i, b'\00'*16)
        ks_block = bytes_to_chunks(ct2, 16)[i]
        pt_block = bytes_xor(ks_block, ct_block)
        plaintext += pt_block
    return strip_pkcs7(plaintext)


if __name__ == "__main__":
    with open("data/25.txt") as f:
        b64 = f.read()
    _plaintext = aes_ecb_dec(b'YELLOW SUBMARINE', b64decode(b64))
    ciphertext = aes_ctr_enc(_key, _plaintext)
    print("Recovered plaintext:")
    print(crack().decode("ascii"))
