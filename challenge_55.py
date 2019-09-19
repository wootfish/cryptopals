import struct

from challenge_08 import bytes_to_chunks
from challenge_30 import r1, r2, md4


# reference: https://link.springer.com/content/pdf/10.1007%2F11426639_1.pdf


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

    def ensure(self, word):
        raise NotImplementedError


class Zeros(Constraint):
    success_message = "0 bit at index {} found"
    failure_message = "0 bit at index {} not found"

    def test(self, ind, word, _):
        return word & (1 << ind) == 0

    def ensure(self, word):
        if self.check(word):
            return word
        raise NotImplementedError


class Ones(Constraint):
    success_message = "1 bit at index {} found"
    failure_message = "1 bit at index {} not found"

    def test(self, ind, word, _):
        return word & (1 << ind) != 0

    def ensure(self, word):
        if self.check(word):
            return word
        raise NotImplementedError


class Eqs(Constraint):
    success_message = "Equality constraint at index {} met"
    failure_message = "Equality constraint at index {} not met"

    def test(self, ind, word_1, word_2):
        return (word_1 ^ word_2) & (1 << ind) == 0

    def ensure(self, word):
        if self.check(word):
            return word
        raise NotImplementedError


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


def check_round_1_constraints(message, quiet=False):
    assert len(message) == 64

    def t(i, cur_word, last_word):
        if not quiet: print("Running tests for i =", i)
        for suite in round_1[i]:
            suite.check(cur_word, last_word, quiet=quiet)
        #zeros, ones, eqs = round_1[i]
        #zeros.check(cur_word, quiet=quiet)
        #ones.check(cur_word, quiet=quiet)
        #eqs.check(cur_word, last_word, quiet=quiet)

    words = bytes_to_chunks(message, 4)
    X = [struct.unpack("<I", word)[0] for word in words]
    a, b, c, d = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    a = r1(a,b,c,d,0x0,3,X);  t(0x0,a,b);  d = r1(d,a,b,c,0x1,7,X);  t(0x1,d,a);  c = r1(c,d,a,b,0x2,11,X);  t(0x2,c,d);  b = r1(b,c,d,a,0x3,19,X);  t(0x3,b,c);
    a = r1(a,b,c,d,0x4,3,X);  t(0x4,a,b);  d = r1(d,a,b,c,0x5,7,X);  t(0x5,d,a);  c = r1(c,d,a,b,0x6,11,X);  t(0x6,c,d);  b = r1(b,c,d,a,0x7,19,X);  t(0x7,b,c);
    a = r1(a,b,c,d,0x8,3,X);  t(0x8,a,b);  d = r1(d,a,b,c,0x9,7,X);  t(0x9,d,a);  c = r1(c,d,a,b,0xA,11,X);  t(0xA,c,d);  b = r1(b,c,d,a,0xB,19,X);  t(0xB,b,c);
    a = r1(a,b,c,d,0xC,3,X);  t(0xC,a,b);  d = r1(d,a,b,c,0xD,7,X);  t(0xD,d,a);  c = r1(c,d,a,b,0xE,11,X);  t(0xE,c,d);  b = r1(b,c,d,a,0xF,19,X);  t(0xF,b,c);


def big_hex_to_lil_bytes(message):
    # perversely, the paper use big-endian format for the messages in its
    # example collisions. this helper function loads that hex into bytes,
    # converting each word from big-endian to little-endian in the process
    # (assuming words are space-delimited)
    return b''.join(bytes.fromhex(h)[::-1] for h in message.split(" "))


if __name__ == "__main__":
    collision_1 = [big_hex_to_lil_bytes("4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 2794bf08 b9e8c3e9"),
                   big_hex_to_lil_bytes("4d7a9c83 d6cb927a 29d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dc8e31 97e31fe5 2794bf08 b9e8c3e9")]
    collision_2 = [big_hex_to_lil_bytes("4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 f713c240 a7b8cf69"),
                   big_hex_to_lil_bytes("4d7a9c83 d6cb927a 29d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f c69d71b3 f9e99198 d79f805e a63bb2e8 45dc8e31 97e31fe5 f713c240 a7b8cf69")]
    print("Checking example collisions from paper...")
    assert md4(collision_1[0]) == md4(collision_1[1])
    assert md4(collision_2[0]) == md4(collision_2[1])
    print("Checking constraints on message 1...")
    check_round_1_constraints(collision_1[0], quiet=True)
    print("Checking constraints on message 2...")
    check_round_1_constraints(collision_2[0], quiet=True)
    print("Constraints met.")
