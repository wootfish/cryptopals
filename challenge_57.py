from itertools import count, chain
from functools import reduce
from operator import mul
from random import randrange

from challenge_31 import do_sha256, hmac
from challenge_39 import egcd


p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
q = 236234353446506858198510045061214171961

j = 30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570


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


def mini_crt(a1, n1, a2, n2):
    m1, m2 = egcd(n1, n2)[1:]
    assert m1*n1 + m2*n2 == 1
    a3 = a1*m2*n2 + a2*m1*n1
    n3 = n1*n2
    return (a3 % n3, n3)


def crt(residues, moduli):
    result = (residues[0], moduli[0])
    for t in zip(residues[1:], moduli[1:]):
        result = mini_crt(*result, *t)
    return result


def bob(message=b"crazy flamboyant for the rap enjoyment", p=p, q=q, g=g,
        pow=pow, get_bytes=lambda n: n.to_bytes(64, 'big')):
    # coroutine: expects DH public keys, yields (message, MAC) pairs
    print("\nBob: Generating DH key.")
    x = randrange(0, q)
    x_pub = pow(g, x, p)  # public key - only yielded, not used
    print(f"Bob: x = {x}")
    print(f"Bob: public key = {x_pub}")
    print()

    h = (yield x_pub)
    while True:
        secret = get_bytes(pow(h, x, p))
        K = do_sha256(secret)
        t = hmac(K, message)
        h = (yield (message, t))


def get_residues(target, moduli, p=p, quiet=True):
    residues = []

    # run the attack once per modulus
    for r in moduli:
        if not quiet: print(end=f"r = {r} ... ", flush=True)

        # randomly search the group for an element h of order r
        while True:
            h = pow(randrange(2, p), (p-1)//r, p)
            if h != 1:
                assert pow(h, r, p) == 1
                break

        # send h, get back a message mac'd by our "shared secret"
        message, t = target.send(h)

        # recover bob's session secret from t
        for i in range(r):
            secret = pow(h, i, p)
            K = do_sha256(secret.to_bytes(64, 'big'))
            if hmac(K, message) == t:
                break

        if not quiet: print("Done.")
        residues.append(i)

    return residues


def main():
    # initialize bob
    b = bob()
    next(b)

    # partially factor j
    print(f"j = {j}")
    j_factors = [p for p in primegen(up_to=2**16)
                 if j % p == 0 and (j // p) % p != 0]  # avoid repeated factors
    print("Some small, non-repeated factors of j:", j_factors)
    print()

    # make sure we've got enough factors to use the CRT
    assert reduce(mul, j_factors, 1) > q

    # collect residues of x mod each j_factor, then apply the CRT
    residues = get_residues(b, j_factors, quiet=False)
    x = crt(residues, j_factors)[0]

    # done!
    print("\nResidue collection complete. Using CRT to derive Bob's secret key...")
    print("x =", x)


if __name__ == "__main__":
    main()
