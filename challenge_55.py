import struct
import random

from itertools import count
from datetime import datetime

from challenge_08 import bytes_to_chunks
from challenge_28 import leftrotate
from challenge_30 import F, r1

from Crypto.Hash import MD4  # way faster than native version from challenge 30


def md4(msg):
    return MD4.new(msg).digest()


# reference: https://link.springer.com/content/pdf/10.1007%2F11426639_1.pdf

# first collision (found after six and a half hours of searching with only round-1 constraints enforced):
# md4(bytes.fromhex('232acb10bc1fed8a286ccf95840c41aa68303defcbfa35e0dd3a4e060fdf71fc94b15959e10faf6da86a740b24ed2da1850fee352735f4752a82ca687e1173d2')) == md4(bytes.fromhex('232acb10bc1fed0a286ccf05840c41aa68303defcbfa35e0dd3a4e060fdf71fc94b15959e10faf6da86a740b24ed2da1850fed352735f4752a82ca687e1173d2')) == b'\x9dR:)\xf6(}\x1c\xd5<\xa8\xc0#\x99\xba?'
# see https://twitter.com/elisohl/status/1176283712838782976


class ConstraintViolatedError(Exception): pass


class Constraint:
    success_message, failure_message = "", ""

    def __init__(self, *inds):
        self.inds = inds

    def test(self, ind, word):
        raise NotImplementedError

    def check(self, word_1, word_2, quiet=True):
        for ind in self.inds:
            if self.test(ind, word_1, word_2):
                if not quiet: print("Check passed:", self.success_message.format(ind))
            else:
                if not quiet: print("Check failed:", self.failure_message.format(ind))
                raise ConstraintViolatedError

    def massage(self, word_1, word_2):
        for ind in self.inds:
            word_1 = self.ensure(ind, word_1, word_2)
        return word_1

    def ensure(self, ind, word_1, word_2):
        raise NotImplementedError


class Zeros(Constraint):
    success_message = "0 bit at index {} found"
    failure_message = "0 bit at index {} not found"

    def test(self, ind, word: int, _):
        return word & (1 << ind) == 0

    def ensure(self, ind, word: int, _):
        mask = (1 << 32) - (1 + (1 << ind))
        return word & mask


class Ones(Constraint):
    success_message = "1 bit at index {} found"
    failure_message = "1 bit at index {} not found"

    def test(self, ind, word, _):
        return word & (1 << ind) != 0

    def ensure(self, ind, word: int, _):
        return word | (1 << ind)


class Eqs(Constraint):
    success_message = "Equality constraint at index {} met"
    failure_message = "Equality constraint at index {} not met"

    def _get_diff(self, ind, word_1, word_2):
        return (word_1 ^ word_2) & (1 << ind)

    def test(self, ind, word_1, word_2):
        return self._get_diff(ind, word_1, word_2) == 0

    def ensure(self, ind, word_1: int, word_2: int):
        return word_1 ^ self._get_diff(ind, word_1, word_2)


round_1 = [[Zeros(), Ones(), Eqs(6)],
           [Zeros(6), Ones(), Eqs(7, 10)],
           [Zeros(10), Ones(6, 7), Eqs(25)],
           [Zeros(7, 10, 25), Ones(6), Eqs()],
           [Zeros(25), Ones(7, 10), Eqs(13)],
           [Zeros(13), Ones(25), Eqs(18, 19, 20, 21)],
           [Zeros(13, 18, 19, 21), Ones(20), Eqs(12, 14)],
           [Zeros(14, 18, 19, 20, 21), Ones(12, 13), Eqs(16)],
           [Zeros(16, 18, 19, 20), Ones(12, 13, 14, 21), Eqs(22, 25)],
           [Zeros(16, 19, 22), Ones(12, 13, 14, 20, 21, 25), Eqs(29)],
           [Zeros(19, 20, 21, 22, 25), Ones(16, 29), Eqs(31)],
           [Zeros(19, 29, 31), Ones(20, 21, 25), Eqs()],
           [Zeros(22, 25, 31), Ones(29), Eqs(26, 28)],
           [Zeros(22, 25, 29), Ones(26, 28, 31), Eqs()],
           [Zeros(26, 28, 29), Ones(22, 25), Eqs(18)],
           [Zeros(18, 29), Ones(25, 26, 28), Eqs()]]


def rrot(word: int, steps: int = 1, length: int = 32) -> int:
    return ((word >> steps) | (word << (length - steps))) & ((1 << length) - 1)


def check_constraints(message, quiet=True):
    assert len(message) == 64

    def f(a, b, c, d, k, s, X):
        # serves as normal round function, but also checks constraint validity
        a = r1(a, b, c, d, k, s, X)
        if not quiet:
            print("Running tests for k =", k)
        for suite in round_1[k]:
            suite.check(a, b, quiet=quiet)
        return a

    X = [struct.unpack("<I", word)[0] for word in bytes_to_chunks(message, 4)]
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    a = f(a,b,c,d,0x0,3,X); d = f(d,a,b,c,0x1,7,X); c = f(c,d,a,b,0x2,11,X); b = f(b,c,d,a,0x3,19,X)
    a = f(a,b,c,d,0x4,3,X); d = f(d,a,b,c,0x5,7,X); c = f(c,d,a,b,0x6,11,X); b = f(b,c,d,a,0x7,19,X)
    a = f(a,b,c,d,0x8,3,X); d = f(d,a,b,c,0x9,7,X); c = f(c,d,a,b,0xA,11,X); b = f(b,c,d,a,0xB,19,X)
    a = f(a,b,c,d,0xC,3,X); d = f(d,a,b,c,0xD,7,X); c = f(c,d,a,b,0xE,11,X); b = f(b,c,d,a,0xF,19,X)


def massage(message, quiet=True):
    assert len(message) == 64

    def f(a, b, c, d, k, s, X):
        # serves as normal round function, but also adjusts X as it goes
        a_new = r1(a, b, c, d, k, s, X)
        if not quiet:
            print(f"m__{k} = {format(X[k], '#034b')}")
        for suite in round_1[k]:
            a_new = suite.massage(a_new, b)
        X[k] = (rrot(a_new, s) - a - F(b, c, d)) % (1 << 32)
        if not quiet:
            print(f"m'_{k} = {format(X[k], '#034b')}\n")
        return a_new

    X = [struct.unpack("<I", word)[0] for word in bytes_to_chunks(message, 4)]
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    a = f(a,b,c,d,0x0,3,X); d = f(d,a,b,c,0x1,7,X); c = f(c,d,a,b,0x2,11,X); b = f(b,c,d,a,0x3,19,X)
    a = f(a,b,c,d,0x4,3,X); d = f(d,a,b,c,0x5,7,X); c = f(c,d,a,b,0x6,11,X); b = f(b,c,d,a,0x7,19,X)
    a = f(a,b,c,d,0x8,3,X); d = f(d,a,b,c,0x9,7,X); c = f(c,d,a,b,0xA,11,X); b = f(b,c,d,a,0xB,19,X)
    a = f(a,b,c,d,0xC,3,X); d = f(d,a,b,c,0xD,7,X); c = f(c,d,a,b,0xE,11,X); b = f(b,c,d,a,0xF,19,X)

    return b''.join(struct.pack("<I", word) for word in X)


def apply_differential(m):
    words = bytes_to_chunks(m, 4)
    for i, delta in ((1, 1 << 31), (2, (1 << 31) - (1 << 28)), (12, -(1 << 16))):
        m_i = (struct.unpack("<I", words[i])[0] + delta) % (1 << 32)
        words[i] = struct.pack("<I", m_i)
    m_prime = b''.join(words)
    return m_prime


def big_hex_to_lil_bytes(message):
    """
    Perversely, the paper use big-endian format for the messages in its example
    collisions. this helper function loads that hex into bytes, converting each
    word from big-endian to little-endian in the process (assuming that words
    are space-delimited, as they are in the paper).
    """
    return b''.join(bytes.fromhex(h)[::-1] for h in message.split(" "))


collision_1 = [big_hex_to_lil_bytes("4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 2794bf08 b9e8c3e9"),
               big_hex_to_lil_bytes("4d7a9c83 d6cb927a 29d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dc8e31 97e31fe5 2794bf08 b9e8c3e9")]
collision_2 = [big_hex_to_lil_bytes("4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 f713c240 a7b8cf69"),
               big_hex_to_lil_bytes("4d7a9c83 d6cb927a 29d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dc8e31 97e31fe5 f713c240 a7b8cf69")]


if __name__ == "__main__":
    print("Running tests.")
    assert rrot(leftrotate(123456789, 10), 10) == 123456789
    for collision in (collision_1, collision_2):
        assert md4(collision[0]) == md4(collision[1])
        check_constraints(collision[0])  # raises exception on failure
        assert massage(collision[0]) == collision[0]  # shouldn't need to correct any constraints
        assert apply_differential(collision[0]) == collision[1]
    message = massage(b'\x00'*64)
    check_constraints(message)
    print("Tests passed.")

    print(datetime.now())
    print("Searching for collisions..", end='')
    for i in count():
        if i & 0xFFFF == 0:
            print(end=".", flush=True)

        orig = random.getrandbits(512).to_bytes(64, 'big')
        m1 = massage(orig)
        m2 = apply_differential(m1)

        # uncomment to confirm massaging is working (disabled for speed)
        #try:
        #    check_constraints(m1)
        #except ConstraintViolatedError:
        #    print("Constraint violation detected: massaging message", orig.hex(), "failed")

        if md4(m1) == md4(m2):
            print()
            print(datetime.now())
            print("Collision found!!")
            print(f"md4(bytes.fromhex('{m1.hex()}')) = {md4(m1)}")
            print(f"md4(bytes.fromhex('{m2.hex()}')) = {md4(m2)}")
            print()
