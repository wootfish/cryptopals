from itertools import count
from random import randrange
from math import log

from challenge_39 import invmod
from challenge_57 import bob, get_small_non_repeated_factors, get_residues


a = -95051
b = 11279326

p = 233970423115425145524320034830162017933

base_pt = (182, 85518893674295321206118380980485522083)
base_pt_order = 233970423115425145498902418297807005944

identity = object()


def ec_inv(pt, p=p):
    x, y = pt
    return (x, p-y)


def ec_add(pt1, pt2, p=p, a=a):
    if pt1 is identity:
        return pt2
    if pt2 is identity:
        return pt1
    if pt1 == ec_inv(pt2, p=p):
        return identity

    x1, y1 = pt1
    x2, y2 = pt2

    if pt1 == pt2:
        top = (3 * x1**2 + a) % p
        btm = (2 * y1) % p
    else:
        top = (y2 - y1) % p
        btm = (x2 - x1) % p

    m = (top * invmod(btm, p)) % p
    x3 = (m**2 - x1 - x2) % p
    y3 = (m*(x1 - x3) - y1) % p

    return (x3, y3)


def ec_mul(pt, k, p=p, a=a):
    result = identity
    while k:
        if k & 1:
            result = ec_add(result, pt, p=p, a=a)
        pt = ec_add(pt, pt, p=p, a=a)
        k >>= 1
    return result


# we could write a generic version of ec_mul that takes either ints or EC
# points... we could, but we won't, for the same reason we're using ec_add
# instead of defining an ECPoint class and giving it a __add__ method: because
# unnecessary complexity is just showboating, and showboating for its own sake
# would distract us from what's actually important in any given challenge.


def test_ecdh():
    # assert that base point is on the curve and that it has the expected order
    print("Running basic fault checks.")
    assert (base_pt[1] ** 2) % p == (base_pt[0] ** 3 + a*base_pt[0] + b) % p
    assert ec_mul(base_pt, base_pt_order) is identity
    print("All good.")
    print("Testing ECDH key agreement.")

    priv_a = randrange(0, base_pt_order)  # alice's private key
    priv_b = randrange(0, base_pt_order)  # bob's private key

    pub_a = ec_mul(base_pt, priv_a)  # alice's public key
    pub_b = ec_mul(base_pt, priv_b)  # bob's public key

    sec_a = ec_mul(pub_b, priv_a)  # shared secret (alice's copy)
    sec_b = ec_mul(pub_a, priv_b)  # shared secret (bob's copy)

    print("Alice's version of shared secret:", sec_a)
    print("Bob's   version of shared secret:", sec_b)
    assert sec_a == sec_b
    print("ECDH successful.")


def point_to_bytes(pt):
    # quick & dirty hack for turning an EC point into something we can hash.
    # this assumes log(p, 2) < 128
    return pt[0].to_bytes(128, 'big') + pt[1].to_bytes(128, 'big')


class NoQuadraticResidueError(Exception):  pass


def tonelli_shanks(n, p):
    if pow(n, (p - 1) // 2, p) != 1:
        print("the residue just doesn't exist")
        raise NoQuadraticResidueError

    # ref: https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm

    # factor as many 2s out of 2 as we can; store the 2's exponent as S and the
    # quotient (n // 2**S) as Q
    Q, S = n, 0
    while Q % 2 == 0:
        Q //= 2
        S += 1

    # find some z which isn't a quadratic residue (tested w/ euler's criterion)
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    # main loop - initialize
    M = S
    c = pow(z, Q, p)
    t = pow(n, Q, p)
    R = pow(n, (Q+1) // 2, p)

    # main loop - execute
    while t > 1:
        # find i's value using repeated squaring
        t_sq = t
        for i in count(1):
            t_sq = pow(t_sq, 2, p)
            if t_sq == 1:
                break
            assert i < M  # sanity-check: if i >= M the residue doesn't exist
                          # (shouldn't ever happen - we made sure the residue
                          # exists back at the top of this function)

        # update state variables and loop
        exponent = M - i - 1
        if exponent < 0:
            b = pow(c, 2**(-exponent), p)
            b = (b * invmod(c, p)) % p
        else:
            b = pow(c, 2**exponent, p)

        M = i
        c = pow(b, 2, p)
        t = (t * c) % p
        R = (R * b) % p

    return 0 if t == 0 else R


def find_point_of_order_r(r, p, a=a, b=b, base=base_pt, order=base_pt_order):
    new_order = order // r
    while True:
        # generate a random point
        x = randrange(0, p)
        rhs = (pow(x, 3, p) + a*x + b) % p
        try:
            y = tonelli_shanks(rhs, p)
        except NoQuadraticResidueError:
            continue
        print("hey")
        pt = (x, y)

        # multiply pt by q // r to see whether pt has order r; if so, return pt
        if ec_mul(pt, new_order) is not identity:
            return pt


def test_point_generation():
    print("Running basic test for Tonelli-Shanks sqrt & random point generation.")
    assert 1 == tonelli_shanks(1, 17)
    assert 2 == tonelli_shanks(4, 17)
    assert 3 == tonelli_shanks(9, 17)
    assert 4 == tonelli_shanks(16, 17)
    assert 5 == tonelli_shanks(8, 17)
    assert 6 == tonelli_shanks(2, 17)
    assert 7 == tonelli_shanks(15, 17)
    pt = find_point_of_order_r(45361, p, b=210)
    assert ec_mul(pt, 45361, p) == 1


def crack_ecdh():
    bobert = bob(g=base_pt, pow=ec_mul, get_bytes=point_to_bytes)  # so named to avoid overwriting the "b" curve parameter
    next(bobert)

    new_curves = ((210, 233970423115425145550826547352470124412),
                  (504, 233970423115425145544350131142039591210),
                  (727, 233970423115425145545378039958152057148))

    moduli = []
    residues = []
    for b, order in new_curves:
        print("Nowing using b =", b)
        print(end="Partially factoring curve's order... ", flush=True)
        divisors = get_small_non_repeated_factors(order)
        new_divs = [d for d in divisors if d not in moduli]
        moduli += new_divs
        print("Done.")

        if new_divs:
            print("Found new divisors:", new_divs)
            print(end="Gathering residues... ", flush=True)
            residues += get_residues(bobert, new_divs, p, pow=ec_mul,
                    get_bytes=point_to_bytes,
                    get_random_point=lambda r, p: find_point_of_order_r(r, p, b))
            print("Done.")
        else:
            print("No new divisors found.")


def main():
    test_ecdh()
    print()
    test_point_generation()
    print()
    crack_ecdh()


if __name__ == "__main__":
    main()
