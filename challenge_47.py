from challenge_39 import RSA

from itertools import count
from random import randrange
from sys import urandom


def pkcs1(D: bytes):
    assert len(D) <= k-11
    ps = urandom(32 - (3+len(D)))
    return b'\x00\x02' + ps + b'\x00' + D


if __name__ == "__main__":
    B = 2 ** (8 * (32-2))
    RSA.default_prime_size = 128
    r = RSA()

    def oracle(ct: int):
        pt = r.dec(ct).to_bytes(32, 'big')
        return pt.startswith(b'\x00\x02')

    _m = int.from_bytes(pkcs1(b'kick it, CC'), 'big')
    c = r.enc(_m)

    #### attack begins

    # step 1
    while True:
        s0 = randrange(2**255)
        c0 = (c * r.enc(s0)) % r.n
        if oracle(c0): break

    s_i = [s0]
    c_i = [c0]
    M_i = [{(2*B, 3*B-1)}]
    i = 1

    # steps 2 thru 4
    while True:
        # step 2.a
        if i == 1:
            for s1 in count(r.n//(3*B)):
                if oracle((c0 * r.enc(s1)) % r.n):
                    break
            s_i.append(s1)

        else:
            # step 2.b
            if len(M_i[i-1]) > 1:
                raise Exception("TODO")

            # step 2.c
            else:
                raise Exception("TODO")

        # step 3
        raise Exception("TODO")

        # step 4
        if len(M_i[i]) == 1:
            a, b = M_i[i][0]
            if a == b:
                m = (a * invmod(s0, r.n)) % r.n
                break
        i += 1

    assert m == _m
