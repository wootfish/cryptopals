from challenge_39 import invmod

from random import randrange
from itertools import count


class Zero:
    pass


class Curve:
    def __init__(self, a, b, p):
        self.zero = Zero()
        self.a = a
        self.b = b
        self.p = p

    def inv(self, pt):
        x, y = pt
        p = self.p
        return (x, p-y)  # = (x, -y) in GF(p)

    def add(self, p1, p2):  # don't worry about how this works. it's ~magic~
        zero = self.zero
        if p1 is zero: return p2
        if p2 is zero: return p1
        if p1 == self.inv(p2): return zero

        a, p = self.a, self.p
        x1, y1 = p1
        x2, y2 = p2

        if p1 == p2:
            top = (3 * x1**2 + a) % p
            btm = (2 * y1) % p
        else:
            top = (y2 - y1) % p
            btm = (x2 - x1) % p
        m = (top * invmod(btm, p)) % p

        x3 = (m**2 - x1 - x2) % p
        y3 = (m*(x1 - x3) - y1) % p
        return x3, y3

    def mul(self, pt, k):
        result = self.zero
        add = self.add
        while k:
            if k & 1:
                result = add(result, pt)
            pt = add(pt, pt)
            k >>= 1
        return result


class NoQuadraticResidueError(Exception):  pass


def eulers_criterion(n, p):
    # tests whether n is a quadratic residue mod p
    # (i.e. whether there exists x such that pow(x, 2, p) == n)
    return pow(n, (p-1)//2, p) == 1


# fast modular square root algorithm
def tonelli_shanks(n, p):
    if not eulers_criterion(n, p):
        raise NoQuadraticResidueError

    # ref: https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm

    # 1. find Q, S such that Q is odd and Q * 2**S = p-1
    Q, S = p-1, 0
    while Q & 1 == 0:  # faster than Q % 2 == 0
        Q >>= 1  # faster than Q //= 2
        S += 1

    # 2. find some int z such that z is not a quadratic residue mod p
    z = 2
    while eulers_criterion(z, p):
        z += 1
        assert z < p

    # 3. initialize main loop's state variables
    M = S
    c = pow(z, Q, p)
    t = pow(n, Q, p)
    R = pow(n, (Q+1) // 2, p)

    # 4. main loop
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

    if t == 0:
        return 0

    res1 = R
    res2 = (-R) % p
    return res1, res2


def find_point_of_order_r(r, curve, curve_order):
    a, b, p, zero = curve.a, curve.b, curve.p, curve.zero

    while True:
        # generate a random point
        x = randrange(0, p)

        # plug x into the curve eqn to find y^2
        rhs = (pow(x, 3, p) + a*x + b) % p

        # go from y^2 to y
        try:
            y = tonelli_shanks(rhs, p)[0]  # arbitrarily use the 1st residue returned by t_s
        except NoQuadraticResidueError:
            continue
        pt = (x, y)

        # test whether pt has order r; if so, return pt
        pt2 = curve.mul(pt, curve_order // r)
        if pt2 is not zero:
            assert curve.mul(pt2, r) is zero
            return pt2


if __name__ == "__main__":
    print("challenge_59.py: this script is meant to be imported, not executed!")
    print("(you're probably looking for challenge_59.ipynb)")
