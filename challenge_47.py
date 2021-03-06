from itertools import count
from typing import List, Tuple, Optional
from math import ceil
from os import urandom

from challenge_39 import RSA


# ref: http://archiv.infsec.ethz.ch/education/fs08/secsem/Bleichenbacher98.pdf


def pkcs1(m: bytes, mod_size: int = 32) -> bytes:
    assert len(m) <= mod_size-11  # we need len(ps) >= 8, meaning len(d) <= 32 - (8+3)
    ps = urandom(mod_size - (3+len(m)))
    return b'\x00\x02' + ps + b'\x00' + m


RANGES = List[Tuple[int, int]]
def intersect(r1: RANGES, r2: RANGES) -> RANGES:
    # textbook algorithm. returns the intersection of the ranges in r1 and r2,
    # where r1 and r2 are ordered lists of ordered pairs
    result = []  # type: RANGES
    i, j = 0, 0
    while i < len(r1) and j < len(r2):      # look for overlaps
        a, b = r1[i]
        c, d = r2[j]
        if b < d: i += 1
        else: j += 1
        if b >= c and d >= a:
            seq = sorted((a, b, c, d))
            result.append((seq[1], seq[2]))
    for ri in range(len(result)-1):         # merge adjacent ranges
        if 0 <= result[ri+1][0] - result[ri][1] <= 1:
            result[ri:ri+2] = [(result[ri][0], result[ri+1][1])]
    return result


if __name__ == "__main__":
    B = 2 ** (8 * (32-2))
    RSA.default_prime_size = 128
    rsa = RSA()

    _m = int.from_bytes(pkcs1(b'kick it, CC'), 'big')
    c = rsa.enc(_m)


    #### helpers

    def oracle(ct: int) -> bool:
        pt = rsa.dec(ct).to_bytes(32, 'big')
        return pt.startswith(b'\x00\x02')

    def trial(pt: int) -> bool:
        return oracle((rsa.enc(pt) * c) % rsa.n)

    assert oracle(c)


    #### attack primitives

    def step_2a() -> int:
        lb = ceil(rsa.n / (3*B))
        for s in count(lb):
            if trial(s):
                return s
        raise Exception

    def step_2b(s_i: int) -> int:
        for s in count(s_i+1):
            if trial(s):
                return s
        raise Exception

    def step_2c(M: RANGES, s: int) -> int:  # the s arg here is s_{i-1} in the paper's notation
        a, b = M[0]
        assert a < b
        r_lb = (2*(b*s - 2*B) + rsa.n - 1) // rsa.n
        for r in count(r_lb):
            s_lb = (2*B + r*rsa.n) // b
            s_ub = (3*B + r*rsa.n) // a
            for s in range(s_lb, s_ub + 1):
                if trial(s):
                    return s
        raise Exception

    def step_3(M: RANGES, s_i: int) -> RANGES:
        ranges = []
        for a, b in M:
            r_lo = (a*s_i - 3*B + 1) // rsa.n
            r_hi = (b*s_i - 2*B) // rsa.n
            for r in range(r_lo, r_hi+1):
                r_a = (2*B + r*rsa.n + s_i - 1) // s_i
                r_b = (3*B - 1 + r*rsa.n) // s_i
                ranges.append((r_a, r_b))
                r += 1
        return intersect(M, ranges)

    def step_4(M: RANGES) -> Optional[int]:
        if len(M) == 1 and M[0][0] == M[0][1]:
            return M[0][0]  # = (a * invmod(s_0, rsa.n)) % rsa.n since s_0 = 1
        return None


    #### attack begins

    M = [(2*B, 3*B-1)]

    print("Starting search.\n")

    for i in count(1):
        print(end=".", flush=True)

        if i == 1: s_i = step_2a()
        elif len(M) > 1: s_i = step_2b(s_i)
        else: s_i = step_2c(M, s_i)

        M = step_3(M, s_i)
        m = step_4(M)
        if m is not None: break

    assert m is not None
    print("\n\n")
    print("Recovered (padded) message:", m.to_bytes(32, 'big'))
    assert m == _m
