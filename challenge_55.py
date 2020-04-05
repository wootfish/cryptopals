import struct
import random

from itertools import count
from datetime import datetime

from challenge_08 import bytes_to_chunks
from challenge_28 import leftrotate
from challenge_30 import F, G, r1, r2, r3

from Crypto.Hash import MD4  # way faster than the native version from challenge 30


MODULUS = 1 << 32


def md4(msg: bytes) -> bytes:
    return MD4.new(msg).digest()


def bin32(n):
    return bin(n)[2:].rjust(32, '0')


# reference: https://link.springer.com/content/pdf/10.1007%2F11426639_1.pdf
# for results, see https://twitter.com/elisohl/status/1176283712838782976


class ConstraintViolatedError(Exception): pass


class Constraint:
    def __init__(self, *inds):
        self.inds = inds
        self.mask = 0
        for ind in inds:
            self.mask |= (1 << ind)
        self.mask_inv = self.mask ^ 0xFFFFFFFF

    def __repr__(self):
        return f"{self.__class__.__name__}({', '.join(str(ind) for ind in self.inds)})"


class Zeros(Constraint):
    def check(self, word_1: int, word_2: int):
        return word_1 & self.mask == 0

    def massage(self, word_1: int, word_2: int):
        return word_1 & self.mask_inv


class Ones(Constraint):
    def check(self, word_1, word_2):
        return word_1 & self.mask == self.mask

    def massage(self, word_1, word_2):
        return word_1 | self.mask


class Eqs(Constraint):
    def check(self, word_1, word_2):
        return (word_1 & self.mask) == (word_2 & self.mask)

    def massage(self, word_1, word_2):
        return (word_1 & self.mask_inv) | (word_2 & self.mask)


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
           [Eqs(18), Eqs(25, 26, 28, 31)],  # d_5 has equality constraints for both a_5 & b_4
           [Eqs(25, 26, 28, 29, 31)],
           [Zeros(31), Ones(29), Eqs(28)],
           [Ones(28)]]


def rrot(word: int, steps: int = 1, length: int = 32) -> int:
    return ((word >> steps) | (word << (length - steps))) & ((1 << length) - 1)


def check_constraints(message, quiet=True):
    assert len(message) == 64

    # checks for constraints that have been enforced have been commented out;
    # uncomment to see how frequently they happen to be satisfied by chance

    def f(a, b, c, d, k, s, X):
        # serves as normal round function, but also checks constraint validity
        a = r1(a, b, c, d, k, s, X)
        if not quiet:
            print("Running tests for k =", k)
        for suite in round_1[k]:
            if not suite.check(a, b):
                print("WARNING: constraint check failed for k =", k)
                print("         suite:", suite)
                raise ConstraintViolatedError
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
        suite.check(a, c)

    # d5
    if not quiet: print("d_5")
    d = r2(d,a,b,c,0x4,5,X)
    round_2[1][0].check(d, a)
    round_2[1][1].check(d, b)

    # c5, b5
    c = r2(c,d,a,b,0x8,9,X)
    # round_2[2][0].check(c, d)

    b = r2(b,c,d,a,12,13,X)
    # for suite in round_2[3]:
    #     suite.check(b, c)

    # a6
    if not quiet: print("a_6")
    a = r2(a,b,c,d,1,3,X)
    round_2[4][0].check(a, b)

    # d6
    d = r2(d,a,b,c,5,5,X)
    # Eqs(28).check(d, b)

    # c6
    c = r2(c,d,a,b,9,9,X)
    # Eqs(28).check(c, d)
    # if c & (1 << 29) == d & (1 << 29):
    #     raise ConstraintViolatedError
    # if c & (1 << 31) == d & (1 << 31):
    #     raise ConstraintViolatedError

    # skip ahead to b9
    b = r2(b,c,d,a,13,13,X)
    a = r2(a,b,c,d,2,3,X); d = r2(d,a,b,c,6,5,X); c = r2(c,d,a,b,10,9,X); b = r2(b,c,d,a,14,13,X)
    a = r2(a,b,c,d,3,3,X); d = r2(d,a,b,c,7,5,X); c = r2(c,d,a,b,11,9,X); b = r2(b,c,d,a,15,13,X)
    a = r3(a,b,c,d,0,3,X); d = r3(d,a,b,c,8,9,X); c = r3(c,d,a,b,4,11,X); b = r3(b,c,d,a,12,15,X)
    # if b & (1 << 31) == 0:
    #     raise ConstraintViolatedError

    # a10
    a = r3(a,b,c,d,2,3,X)
    # if a & (1 << 31) == 0:
    #     raise ConstraintViolatedError


def massage(message, quiet=True):
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
        # returns a message value tailored to produce the expected intermediate state
        return (rrot(state_log[k+4], rot) - state_log[k] - F(state_log[k+3], state_log[k+2], state_log[k+1])) % MODULUS

    a = f(a,b,c,d,0x0,3,X); d = f(d,a,b,c,0x1,7,X); c = f(c,d,a,b,0x2,11,X); b = f(b,c,d,a,0x3,19,X)
    a = f(a,b,c,d,0x4,3,X); d = f(d,a,b,c,0x5,7,X); c = f(c,d,a,b,0x6,11,X); b = f(b,c,d,a,0x7,19,X)
    a = f(a,b,c,d,0x8,3,X); d = f(d,a,b,c,0x9,7,X); c = f(c,d,a,b,0xA,11,X); b = f(b,c,d,a,0xB,19,X)
    a = f(a,b,c,d,0xC,3,X); d = f(d,a,b,c,0xD,7,X); c = f(c,d,a,b,0xE,11,X); b = f(b,c,d,a,0xF,19,X)

    # enforce round 2 constraints

    # these are a little more involved than round 1 constraints because we need to keep them from stomping on the round
    # 1 changes we've made

    ROUND_2_CONST = 0x5A827999  # constant from addition step in r2 round function

    ######## a5
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

    ######## d5
    N_1 = (state_log[4] + F(state_log[7], state_log[6], state_log[5])) % MODULUS
    N_2 = (d + G(a, b, c) + ROUND_2_CONST) % MODULUS
    m_4 = 0
    b_rot = rrot(b, 5)

    def set_d5_bit(N_orig, m, ind, x):
        N = (N_orig + m) % MODULUS
        return (N & (1 << ind)) ^ x

    m_4 |= set_d5_bit(N_1, m_4, 4, 1 << 4)
    m_4 |= set_d5_bit(N_1, m_4, 7, 1 << 7)
    m_4 |= set_d5_bit(N_1, m_4, 10, (state_log[7] >> 3) & (1 << 10))
    m_4 |= set_d5_bit(N_2, m_4, 13, (a >> 5) & (1 << 13))
    m_4 |= set_d5_bit(N_2, m_4, 20, b_rot & (1 << 20))
    m_4 |= set_d5_bit(N_2, m_4, 21, b_rot & (1 << 21))
    m_4 |= set_d5_bit(N_1, m_4, 22, 0)
    m_4 |= set_d5_bit(N_2, m_4, 23, b_rot & (1 << 23))
    m_4 |= set_d5_bit(N_2, m_4, 24, b_rot & (1 << 24))
    m_4 |= set_d5_bit(N_2, m_4, 26, b_rot & (1 << 26))

    X[4] = m_4
    d = r2(d, a, b, c, 4, 5, X)

    # re-massage a_2 and make sure d_2's equality constraints with a2 still hold
    state_log[8] = r1(state_log[4], state_log[7], state_log[6], state_log[5], 4, 3, X)
    state_log[9] = round_1[5][2].massage(state_log[9], state_log[8])

    # contain the effects of these changes to a_2 and d_2
    X[5] = (rrot(state_log[9], 7) - state_log[5] - F(state_log[8], state_log[7], state_log[6])) % MODULUS
    X[6] = r1_inv(6, 11)
    X[7] = r1_inv(7, 19)
    X[8] = r1_inv(8, 3)
    X[9] = r1_inv(9, 7)

    ######## c5 and b5 (just skip over these two)
    c = r2(c,d,a,b,8,9,X)
    b = r2(b,c,d,a,12,13,X)

    ######## a6
    a_5 = a
    a = r2(a,b,c,d,1,3,X)
    a = round_2[4][0].massage(a, b)
    X[1] = (rrot(a, 3) - a_5 - G(b, c, d) - ROUND_2_CONST) % MODULUS
    state_log[5] = r1(state_log[1], state_log[4], state_log[3], state_log[2], 1, 7, X)

    # could probably get rid of this while loop w/ enough careful analysis
    while (not round_1[1][0].check(state_log[5], None)
           or not round_1[1][1].check(state_log[5], state_log[4])
           or not round_1[2][2].check(state_log[6], state_log[5])):
        X[1] = random.getrandbits(32)
        a = r2(a_5,b,c,d,1,3,X)
        a = round_2[4][0].massage(a, b)
        X[1] = (rrot(a, 3) - a_5 - G(b,c,d) - ROUND_2_CONST) % MODULUS
        state_log[5] = r1(state_log[1], state_log[4], state_log[3], state_log[2], 1, 7, X)

    X[2] = r1_inv(2, 11)
    X[3] = r1_inv(3, 19)
    X[4] = r1_inv(4, 3)
    X[5] = r1_inv(5, 7)

    return b''.join(struct.pack("<I", word) for word in X)


DIFFERENTIALS = ((1, 1 << 31),
                 (2, (1 << 31) - (1 << 28)),
                 (12, -(1 << 16)))


def apply_differential(m):
    words = bytes_to_chunks(m, 4)
    for i, delta in DIFFERENTIALS:
        m_i = (struct.unpack("<I", words[i])[0] + delta) % MODULUS
        words[i] = struct.pack("<I", m_i)
    m_prime = b''.join(words)
    return m_prime


def big_hex_to_lil_bytes(message):
    # Wang et al. use big-endian format for the messages in their example
    # collisions. This helper function loads that hex into bytes, converting
    # each word from big-endian to little-endian in the process (assuming that
    # words are space-delimited, as they are in the paper).
    return b''.join(bytes.fromhex(h)[::-1] for h in message.split(" "))


# collisions from the paper
collision_1 = [big_hex_to_lil_bytes("4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 2794bf08 b9e8c3e9"),
               big_hex_to_lil_bytes("4d7a9c83 d6cb927a 29d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dc8e31 97e31fe5 2794bf08 b9e8c3e9")]
collision_2 = [big_hex_to_lil_bytes("4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 f713c240 a7b8cf69"),
               big_hex_to_lil_bytes("4d7a9c83 d6cb927a 29d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dc8e31 97e31fe5 f713c240 a7b8cf69")]


def run_tests():
    print("Running tests.")
    assert rrot(leftrotate(123456789, 10), 10) == 123456789
    check_constraints(massage(b'\x00'*64))
    check_constraints(massage(b'\x17'*64))
    check_constraints(massage(b'test'*16))
    check_constraints(massage(b'beer'*16))
    check_constraints(massage(b'16-character str'*4))
    for collision in (collision_1, collision_2):
        assert apply_differential(collision[0]) == collision[1]
        assert md4(collision[0]) == md4(collision[1])
        check_constraints(collision[0])
    print("Tests passed.")


def find_collisions(check_constraints=False, report_trial_rate=False):
    if check_constraints:
        failures = 0

    if report_trial_rate:
        from time import perf_counter
        t_0 = perf_counter()

    for i in count():
        # occasionally print something so the user knows we're still running
        if i & 0xFFFF == 10:
            if report_trial_rate:
                print("Trial rate (avg trials per sec):", i / (perf_counter() - t_0))
            else:
                print(".", end="", flush=True)

        # massage some random bytes. if we get a collision then yield (m1, m2)
        orig = random.getrandbits(512).to_bytes(64, 'big')
        m1 = massage(orig)
        m2 = apply_differential(m1)

        if check_constraints:
            # confirm massaging is working (disabled by default for speed)
            try:
                check_constraints(m1)
            except ConstraintViolatedError:
                failures += 1
                print("Constraint violation detected: massaging message", orig.hex(), "failed")
                if i > 0: print("Failure rate:", failures / i)
                print()

        if md4(m1) == md4(m2):
            yield m1, m2  # we've got a hit!


if __name__ == "__main__":
    run_tests()
    print("Searching for collisions...")
    print(datetime.now())
    print()

    for m1, m2 in find_collisions(report_trial_rate=True):
        print()
        print(datetime.now())
        print("Collision found!!")
        print(f"md4(bytes.fromhex('{m1.hex()}')) = {md4(m1)}")
        print(f"md4(bytes.fromhex('{m2.hex()}')) = {md4(m2)}")
        print()
