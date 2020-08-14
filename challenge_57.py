# helper functions moved from challenge_57.ipynb

from itertools import count
from random import randrange

from challenge_31 import do_sha256, hmac
from challenge_39 import egcd


# helper: provides a terse, consistent method for converting ints to bytes
# assumes that n will fit into 64 bytes
def int_to_bytes(n):
    return n.to_bytes(64, 'big')


# generates primes using an unbounded version of the Sieve of Eratosthenes
def primegen(up_to=None):
    yield 2
    d = {}
    counter = count(3, 2) if up_to is None else range(3, up_to, 2)
    for i in counter:
        l = d.pop(i, None)
        if l:
            for n in l:
                d.setdefault(i+(2*n), []).append(n)
            continue
        yield i
        d.setdefault(3*i, []).append(i)


# chinese remainder theorem: main function and helper
def crt(residues, moduli):
    result = (residues[0], moduli[0])
    for t in zip(residues[1:], moduli[1:]):
        result = mini_crt(*result, *t)
    return result


def mini_crt(a1, n1, a2, n2):
    m1, m2 = egcd(n1, n2)[1:]
    assert m1*n1 + m2*n2 == 1
    a3 = a1*m2*n2 + a2*m1*n1
    n3 = n1*n2
    return (a3 % n3, n3)


# these next two are also defined in the notebook's body, but
# i want to make them available to future notebooks as imports

def find_int_of_order_r(r, p):
    while True:
        h = pow(randrange(2, p), (p-1)//r, p)
        if h != 1:
            assert pow(h, r, p) == 1
            return h


def get_residues(target, moduli, p, quiet=True):
    residues = []

    # run the attack once per modulus
    for r in moduli:
        if not quiet: print(end=f"r = {r} ... ", flush=True)

        # randomly search the group for an element h of order r
        h = find_int_of_order_r(r, p)
        while True:
            h = pow(randrange(2, p), (p-1)//r, p)
            if h != 1:
                assert pow(h, r, p) == 1
                break

        # send h, get back a message mac'd by our "shared secret"
        message, t = target.send(h)

        # recover bob's session secret from t
        for i in range(r):
            secret = int_to_bytes(pow(h, i, p))
            K = do_sha256(secret)
            if hmac(K, message) == t:
                break

        if not quiet: print("Done.")
        residues.append(i)

    return residues


if __name__ == "__main__":
    print("challenge_57.py: this script is meant to be imported, not executed!")
    print("(you're probably looking for challenge_57.ipynb)")
