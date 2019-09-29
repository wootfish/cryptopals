import struct
import random

from itertools import count, product
from datetime import datetime

from challenge_02 import bytes_xor
from challenge_08 import bytes_to_chunks
from challenge_28 import leftrotate
from challenge_30 import F, G, r1, r2

from Crypto.Hash import MD4  # way faster than native version from challenge 30


MODULUS = 1 << 32


def md4(msg):
    return MD4.new(msg).digest()


# reference: https://link.springer.com/content/pdf/10.1007%2F11426639_1.pdf
# for results, see https://twitter.com/elisohl/status/1176283712838782976


class ConstraintViolatedError(Exception): pass


class Constraint:
    success_message, failure_message = "", ""

    def __init__(self, *inds):
        self.inds = inds

    @staticmethod
    def test(ind, word):
        raise NotImplementedError

    @staticmethod
    def ensure(self, ind, word_1, word_2):
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


class Zeros(Constraint):
    success_message = "0 bit at index {} found"
    failure_message = "0 bit at index {} not found"

    @staticmethod
    def test(ind, word: int, _):
        return word & (1 << ind) == 0

    @staticmethod
    def ensure(ind, word: int, _):
        mask = MODULUS - (1 + (1 << ind))
        return word & mask


class Ones(Constraint):
    success_message = "1 bit at index {} found"
    failure_message = "1 bit at index {} not found"

    @staticmethod
    def test(ind, word, _):
        return word & (1 << ind) != 0

    @staticmethod
    def ensure(ind, word: int, _):
        return word | (1 << ind)


class Eqs(Constraint):
    success_message = "Equality constraint at index {} met"
    failure_message = "Equality constraint at index {} not met"

    @staticmethod
    def _get_diff(ind, word_1, word_2):
        return (word_1 ^ word_2) & (1 << ind)

    @staticmethod
    def test(ind, word_1, word_2):
        return Eqs._get_diff(ind, word_1, word_2) == 0

    @staticmethod
    def ensure(ind, word_1: int, word_2: int):
        return word_1 ^ Eqs._get_diff(ind, word_1, word_2)


round_1 = [[Eqs(6)],
           [Zeros(6), Eqs(7, 10)],
           [Zeros(10), Ones(6, 7), Eqs(25)],
           [Zeros(7, 10, 25), Ones(6)],
           [Zeros(25), Ones(7, 10), Eqs(13)],
           [Zeros(13), Ones(25), Eqs(18, 19, 20, 21)],
           [Zeros(13, 18, 19, 21), Ones(20), Eqs(12, 14)],
           [Zeros(14, 18, 19, 20, 21), Ones(12, 13), Eqs(16)],
           [Zeros(16, 18, 19, 20), Ones(12, 13, 14, 21), Eqs(22, 25)],
           [Zeros(16, 19, 22), Ones(12, 13, 14, 20, 21, 25), Eqs(29)],
           [Zeros(19, 20, 21, 22, 25), Ones(16, 29), Eqs(31)],
           [Zeros(19, 29, 31), Ones(20, 21, 25)],
           [Zeros(22, 25, 31), Ones(29), Eqs(26, 28)],
           [Zeros(22, 25, 29), Ones(26, 28, 31)],
           [Zeros(26, 28, 29), Ones(22, 25), Eqs(18)],
           [Zeros(18, 29), Ones(25, 26, 28)]]


round_2 = [[Zeros(26), Ones(25, 28, 31), Eqs(18)],
           [Eqs(28, 31)],
           [],  #[Eqs(25, 26, 28, 29, 31)],
           [], #[Zeros(31), Ones(29), Eqs(28)]]
           [Ones(28)]]


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

    if not quiet: print("Running second-round tests")

    # a5
    if not quiet: print("a_5")
    a = r2(a,b,c,d,0x0,3,X)
    for suite in round_2[0]:
        suite.check(a, c, quiet=quiet)

    # d5
    if not quiet: print("d_5")
    d = r2(d,a,b,c,0x4,5,X)
    round_2[1][0].check(d, a, quiet=quiet)

    # c5, b5
    c = r2(c,d,a,b,0x8,9,X)
    b = r2(b,c,d,a,12,13,X)

    # a6
    if not quiet: print("a_6")
    a = r2(a,b,c,d,1,3,X)
    round_2[4][0].check(a, b, quiet=quiet)



def massage(message, quiet=True):
    assert len(message) == 64

    X = [struct.unpack("<I", word)[0] for word in bytes_to_chunks(message, 4)]
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    # enforce round 1 conditions (these are easy to do in bulk)

    state_log = [a, d, c, b]  # keep a record of all intermediate states (needed for round 2 message corrections)
    def f(a, b, c, d, k, s, X):
        # serves as normal round function, but also adjusts X as it goes
        a_new = r1(a, b, c, d, k, s, X)
        if not quiet:
            print(f"m__{k} = {format(X[k], '#034b')}")
        for suite in round_1[k]:
            a_new = suite.massage(a_new, b)
        X[k] = (rrot(a_new, s) - a - F(b, c, d)) % MODULUS
        if not quiet:
            print(f"m'_{k} = {format(X[k], '#034b')}\n")
        state_log.append(a_new)
        return a_new

    def r1_inv(k, rot):
        # returns a message value tailored to produce the expected intermediate states
        return (rrot(state_log[k+4], rot) - state_log[k] - F(state_log[k+3], state_log[k+2], state_log[k+1])) % MODULUS

    a = f(a,b,c,d,0x0,3,X); d = f(d,a,b,c,0x1,7,X); c = f(c,d,a,b,0x2,11,X); b = f(b,c,d,a,0x3,19,X)
    a = f(a,b,c,d,0x4,3,X); d = f(d,a,b,c,0x5,7,X); c = f(c,d,a,b,0x6,11,X); b = f(b,c,d,a,0x7,19,X)
    a = f(a,b,c,d,0x8,3,X); d = f(d,a,b,c,0x9,7,X); c = f(c,d,a,b,0xA,11,X); b = f(b,c,d,a,0xB,19,X)
    a = f(a,b,c,d,0xC,3,X); d = f(d,a,b,c,0xD,7,X); c = f(c,d,a,b,0xE,11,X); b = f(b,c,d,a,0xF,19,X)

    # enforce round 2 constraints

    # these are a bit fussier than round 1 constraints so only the ones that
    # (usually) play nice with round 1 constraints get enforced
    ROUND_2_CONST = 0x5A827999

    # a5
    a_4 = a
    a = r2(a,b,c,d,0,3,X)
    for suite in round_2[0]:
        a = suite.massage(a, c)
    X[0] = (rrot(a, 3) - a_4 - G(b, c, d) - ROUND_2_CONST) % MODULUS
    state_log[4] = r1(state_log[0], state_log[3], state_log[2], state_log[1], 0, 3, X)  # adjust a_1
    X[1] = r1_inv(1, 7);
    X[2] = r1_inv(2, 11);
    X[3] = r1_inv(3, 19);
    X[4] = r1_inv(4, 3)

    # d5
    d_4 = d
    d = r2(d,a,b,c,4,5,X)
    d = round_2[1][0].massage(d, b)
    X[4] = (rrot(d, 5) - d_4 - G(a, b, c) - ROUND_2_CONST) % MODULUS
    state_log[8] = r1(state_log[4], state_log[7], state_log[6], state_log[5], 4, 3, X)  # adjust d_1
    X[5] = r1_inv(5, 7);
    X[6] = r1_inv(6, 11);
    X[7] = r1_inv(7, 19);
    X[8] = r1_inv(8, 3)

    # just skip over these two (c5 and b5)
    c = r2(c,d,a,b,8,9,X)
    b = r2(b,c,d,a,12,13,X)

    # a6
    a_5 = a
    a = r2(a,b,c,d,1,3,X)
    a = round_2[4][0].massage(a, b)
    X[1] = (rrot(a, 3) - a_5 - G(b, c, d) - ROUND_2_CONST) % MODULUS
    state_log[5] = r1(state_log[1], state_log[4], state_log[3], state_log[2], 1, 7, X)
    X[2] = r1_inv(2, 11)
    X[3] = r1_inv(3, 19)
    X[4] = r1_inv(4, 3)
    X[5] = r1_inv(5, 7)

    return b''.join(struct.pack("<I", word) for word in X)


DIFFERENTIALS = ((1, 1 << 31), (2, (1 << 31) - (1 << 28)), (12, -(1 << 16)))
def apply_differential(m):
    words = bytes_to_chunks(m, 4)
    for i, delta in DIFFERENTIALS:
        m_i = (struct.unpack("<I", words[i])[0] + delta) % MODULUS
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

# additional collisions generated on Sept 9, 2019 (only round 1 constraints enforced; avg 11 hours per collision)
collision_3 = [bytes.fromhex('232acb10bc1fed8a286ccf95840c41aa68303defcbfa35e0dd3a4e060fdf71fc94b15959e10faf6da86a740b24ed2da1850fee352735f4752a82ca687e1173d2'),
               bytes.fromhex('232acb10bc1fed0a286ccf05840c41aa68303defcbfa35e0dd3a4e060fdf71fc94b15959e10faf6da86a740b24ed2da1850fed352735f4752a82ca687e1173d2')]
collision_4 = [bytes.fromhex('71342186f79cf951614801861d8f1652917ee6f2d4644431cdd3211d8a30fe91ec1271d9c15aaad70dc69406a7f83206bb09ec3b4e58050bd661597681c4f441'),
               bytes.fromhex('71342186f79cf9d1614801f61d8f1652917ee6f2d4644431cdd3211d8a30fe91ec1271d9c15aaad70dc69406a7f83206bb09eb3b4e58050bd661597681c4f441')]


if __name__ == "__main__":
    print("Running tests.")
    assert rrot(leftrotate(123456789, 10), 10) == 123456789
    for collision in (collision_1, collision_2, collision_3, collision_4):
        assert apply_differential(collision[0]) == collision[1]
        assert md4(collision[0]) == md4(collision[1])

    #for collision in (collision_1, collision_2):
    #    # for some reason these tests don't pass on collision 4 -- maybe it
    #    # doesn't take the same differential path thru later rounds? always
    #    # possible, since these conditions are sufficient but not necessary

    #    check_constraints(collision[0])  # raises exception on failure
    #    assert massage(collision[0]) == collision[0]  # shouldn't need to correct any constraints

    check_constraints(massage(bytes(64)))
    print("Basic tests passed.")

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
        #else:
        #    print("this one's a-ok")

        if md4(m1) == md4(m2):
            print()
            print(datetime.now())
            print("Collision found!!")
            print(f"md4(bytes.fromhex('{m1.hex()}')) = {md4(m1)}")
            print(f"md4(bytes.fromhex('{m2.hex()}')) = {md4(m2)}")
            print()
