from Crypto.Util import number

from challenge_34 import trunc


class InvModException(Exception): pass


def egcd(a, b):
    stack = []
    while a != 0:
        stack.append((a, b))
        a, b = b % a, a

    g, y, x = b, 0, 1

    while stack:
        a, b = stack.pop()
        g, y, x = g, x - (b//a)*y, y

    return g, y, x


def invmod(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise InvModException('no inverse')
    else:
        return x % m


class RSA:
    default_prime_size = 1024
    e = 3

    def __init__(self, p_size=None, p=None, q=None, quiet=True):
        p_size = p_size or self.default_prime_size
        if not quiet: print("Generating p...")
        self._p = p or number.getPrime(p_size)
        if not quiet: print("Generating q...")
        self._q = q or number.getPrime(p_size)
        if not quiet: print("Checking p-1 and q-1 for divisibility by {}...".format(self.e))
        while (self._p-1) % self.e == 0: self._p = number.getPrime(p_size)
        while (self._q-1) % self.e == 0: self._q = number.getPrime(p_size)
        if not quiet: print("p,q generated.")

        self.n = self._p * self._q
        self._et = (self._p-1) * (self._q-1)
        self._d = invmod(self.e, self._et)

        self.pubkey = (self.e, self.n)
        self._privkey = (self._d, self.n)

    def enc(self, pt: int) -> int:
        return pow(pt, self.e, self.n)

    def dec(self, ct: int) -> int:
        return pow(ct, self._d, self.n)


if __name__ == "__main__":
    assert invmod(17, 3120) == 2753
    print("invmod test vector passed.")

    print("\nTrying RSA with p, q = 17, 23")
    rsa = RSA(p=17, q=23)
    print("pubkey: e, n =", rsa.pubkey)

    pt1 = 42
    ct = rsa.enc(pt1)
    pt2 = rsa.dec(ct)

    print(pt1, "encrypted to", ct, "and decrypted to", pt2)
    assert pt1 == pt2
    print("Test with toy primes passed.")

    print("\nTrying RSA with {}-bit bignum primes.".format(rsa.default_prime_size))
    print("Generating keypair...")
    rsa = RSA(quiet=False)
    print("pubkey: e, n =", rsa.pubkey)

    pt_bytes = b'this is when you know who your real friends are'
    pt1 = int.from_bytes(pt_bytes, 'big')
    ct = rsa.enc(pt1)
    pt2 = rsa.dec(ct)

    print("message:", pt_bytes)
    print("encoded:", trunc(hex(pt1)))
    print(trunc(hex(pt1)), "encrypted as", trunc(hex(ct)))
    print(trunc(hex(ct)), "decrypted as", trunc(hex(pt2)))
    assert pt1 == pt2
    print("decoded:", bytes.fromhex(hex(pt2)[2:]))
