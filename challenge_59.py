from itertools import count

from challenge_39 import invmod


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


def main():
    # assert that base point is on the curve and that it has the expected order
    assert (base_pt[1] ** 2) % p == (base_pt[0] ** 3 + a*base_pt[0] + b) % p
    assert ec_mul(base_pt, base_pt_order) is identity


if __name__ == "__main__":
    main()
