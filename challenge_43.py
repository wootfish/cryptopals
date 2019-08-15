from random import SystemRandom

from hashlib import sha1

from challenge_39 import invmod


rng = SystemRandom()


class BadKError(Exception): pass


class DSA:
    # provided parameters
    p = int("800000000000000089e1855218a0e7dac38136ffafa72eda7"
            "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
            "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
            "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
            "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
            "1a584471bb1", base=16)
    q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", base=16)
    g = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
            "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
            "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
            "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
            "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
            "9fc95302291", base=16)

    def __init__(self, x=None, y=None):
        if x is not None:
            self._x = x
            self.y = pow(self.g, x, self.p)
        elif y is not None:
            self.y = y
        else:
            self._x = rng.randrange(1, self.q)
            self.y = pow(self.g, self._x, self.p)

    def sign(self, message, k=None):
        if self._x is None:
            raise Exception("can't sign without private key")

        if k is None:
            while True:
                k = rng.randrange(1, self.q)
                try:
                    return self._sign(message, k)
                except BadKError:
                    pass
        else:
            return self._sign(message, k)

    def _sign(self, message, k):
        r = pow(self.g, k, self.p) % self.q
        if r == 0: raise BadKError()
        kinv = invmod(k, self.q)
        Hm = int(sha1(message).hexdigest(), base=16) % self.q
        s = (kinv * (Hm + self._x * r)) % self.q
        if s == 0: raise BadKError()
        return r, s

    def verify(self, message, signature):
        r, s = signature
        if not 0 < r < self.q or not 0 < s < self.q:
            print("signature params outside valid range")
            return False
        w = invmod(s, self.q)
        Hm = int(sha1(message).hexdigest(), base=16) % self.q
        u1 = (Hm * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q
        return v == r


def recover_x(r, s, k, Hm):
    numerator = (s * k - Hm) % DSA.q
    return (numerator * invmod(r, DSA.q)) % DSA.q


if __name__ == "__main__":
    y = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
            "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
            "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
            "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
            "bb283e6633451e535c45513b2d33c99ea17", base=16)
    message = (b'For those that envy a MC it can be hazardous to your health\n'
               b'So be friendly, a matter of life and death, just like a etch-a-sketch\n')
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    sig = (r, s)

    Hm = int(sha1(message).hexdigest(), base=16)

    print("Running tests.")
    assert Hm == 0xd2d0714f014a9784047eaeccf956520045c45265
    assert DSA(y=y).verify(message, (r, s))
    d = DSA()
    assert d.verify(message, d.sign(message))
    assert recover_x(*d.sign(message, 17), 17, Hm) == d._x
    print("Tests passed.")

    target = "0954edd5e0afe5542a4adf012611a91912a3ec16"

    print("Searching k values from 0 to 2**16..", end="")
    for k in range(2**16):
        if k % 1024 == 0:
            print(".", end='', flush=True)
        x = recover_x(r, s, k, Hm)
        x_hex = hex(x)[2:].encode('ascii')
        if sha1(x_hex).hexdigest() == target:
            print("\nValid k found!")
            print("k =", k)
            print("x =", x)
            break
    else:
        print("\nNo valid k found.")


