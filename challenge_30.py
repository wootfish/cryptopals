from challenge_08 import bytes_to_chunks
from challenge_28 import leftrotate

import struct
from typing import Optional, Sequence


# custom MD4 implementation based on RFC: https://tools.ietf.org/html/rfc1320


DEBUG = False


def get_padding(message: bytes) -> bytes:
    ml = 8*len(message)  # message length, in bits
    pl = 511 - ((ml - 448) % 512)  # number of zero bits to pad with
    padding = b'\x80'
    padding += b'\x00' * (pl//8)
    padding += struct.pack(">Q", ml)[::-1]  # this dumb [::-1] thing is where this padding function differs from the normal one
    return padding


def F(x: int, y: int, z: int) -> int: return (x & y) | ((x ^ 0xFFFFFFFF) & z)
def G(x: int, y: int, z: int) -> int: return (x & y) | (x & z) | (y & z)
def H(x: int, y: int, z: int) -> int: return x ^ y ^ z


def r1(a: int, b: int, c: int, d: int, k: int, s: int, X: Sequence[int]) -> int:
    val = (a + F(b, c, d) + X[k]) % 2**32
    return leftrotate(val, s)


def r2(a: int, b: int, c: int, d: int, k: int, s: int, X: Sequence[int]) -> int:
    val = (a + G(b, c, d) + X[k] + 0x5A827999) % 2**32
    return leftrotate(val, s)


def r3(a: int, b: int, c: int, d: int, k: int, s: int, X: Sequence[int]) -> int:
    val = (a + H(b, c, d) + X[k] + 0x6ED9EBA1) % 2**32
    return leftrotate(val, s)


def md4(message: bytes, state: Optional[Sequence[int]] = None) -> bytes:
    padding = get_padding(message)
    message += padding

    a, b, c, d = state or (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
    if DEBUG: print("   ", hex(a), hex(b), hex(c), hex(d))

    for block in bytes_to_chunks(message, 64):
        words = bytes_to_chunks(block, 4)
        X = [struct.unpack("<I", word)[0] for word in words]
        aa, bb, cc, dd = a, b, c, d

        # round 1
        a = r1(a,b,c,d, 0,3,X); d = r1(d,a,b,c, 1,7,X); c = r1(c,d,a,b, 2,11,X); b = r1(b,c,d,a, 3,19,X)
        a = r1(a,b,c,d, 4,3,X); d = r1(d,a,b,c, 5,7,X); c = r1(c,d,a,b, 6,11,X); b = r1(b,c,d,a, 7,19,X)
        a = r1(a,b,c,d, 8,3,X); d = r1(d,a,b,c, 9,7,X); c = r1(c,d,a,b,10,11,X); b = r1(b,c,d,a,11,19,X)
        a = r1(a,b,c,d,12,3,X); d = r1(d,a,b,c,13,7,X); c = r1(c,d,a,b,14,11,X); b = r1(b,c,d,a,15,19,X)
        if DEBUG: print("1  ", hex(a), hex(b), hex(c), hex(d))

        # round 2
        a = r2(a,b,c,d,0,3,X); d = r2(d,a,b,c,4,5,X); c = r2(c,d,a,b, 8,9,X); b = r2(b,c,d,a,12,13,X)
        a = r2(a,b,c,d,1,3,X); d = r2(d,a,b,c,5,5,X); c = r2(c,d,a,b, 9,9,X); b = r2(b,c,d,a,13,13,X)
        a = r2(a,b,c,d,2,3,X); d = r2(d,a,b,c,6,5,X); c = r2(c,d,a,b,10,9,X); b = r2(b,c,d,a,14,13,X)
        a = r2(a,b,c,d,3,3,X); d = r2(d,a,b,c,7,5,X); c = r2(c,d,a,b,11,9,X); b = r2(b,c,d,a,15,13,X)
        if DEBUG: print("2  ", hex(a), hex(b), hex(c), hex(d))

        # round 3
        a = r3(a,b,c,d,0,3,X); d = r3(d,a,b,c, 8,9,X); c = r3(c,d,a,b,4,11,X); b = r3(b,c,d,a,12,15,X)
        a = r3(a,b,c,d,2,3,X); d = r3(d,a,b,c,10,9,X); c = r3(c,d,a,b,6,11,X); b = r3(b,c,d,a,14,15,X)
        a = r3(a,b,c,d,1,3,X); d = r3(d,a,b,c, 9,9,X); c = r3(c,d,a,b,5,11,X); b = r3(b,c,d,a,13,15,X)
        a = r3(a,b,c,d,3,3,X); d = r3(d,a,b,c,11,9,X); c = r3(c,d,a,b,7,11,X); b = r3(b,c,d,a,15,15,X)
        print("3  ", hex(a), hex(b), hex(c), hex(d))

        # increment registers by their initial values
        a = (a + aa) % 2**32
        b = (b + bb) % 2**32
        c = (c + cc) % 2**32
        d = (d + dd) % 2**32
        print("inc", hex(a), hex(b), hex(c), hex(d))

    return b''.join(struct.pack("<L", r) for r in (a, b, c, d))


if __name__ == "__main__":
    assert md4(b"") == bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")
    assert md4(b"a") == bytes.fromhex("bde52cb31de33e46245e05fbdbd6fb24")
    assert md4(b"abc") == bytes.fromhex("a448017aaf21d8525fc10ae87aa6729d")
    assert md4(b"message digest") == bytes.fromhex("d9130a8164549fe818874806e1c7014b")
    assert md4(b"abcdefghijklmnopqrstuvwxyz") == bytes.fromhex("d79e1c308aa5bbcdeea8ed63df412da9")
    assert md4(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") == bytes.fromhex("043f8582f241db351ce627e153e7f0e4")
    assert md4(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890") == bytes.fromhex("e33b4ddc9c38f2199c3e7b164fcc0536")
    print("md4 test vectors passed.")

    
