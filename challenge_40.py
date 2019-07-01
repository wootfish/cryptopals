from challenge_34 import trunc
from challenge_39 import RSA, invmod

from sympy import S, N, Rational


if __name__ == "__main__":
    pt = b'slowly we unfold as lotus flowers'
    p = int.from_bytes(pt, 'big')

    print("Message:", pt)
    print("Encoded:", hex(p))

    print("Generating {}-bit RSA keypairs...".format(RSA.default_prime_size))
    rsa = [RSA(quiet=False) for _ in range(3)]
    print("Encrypting plaintexts...", end=" ", flush=True)

    c = [r.enc(p) for r in rsa]
    print("Done.\nSanity-checking encryption...", end=" ", flush=True)
    assert rsa[0].dec(c[0]) == p
    print("Done.\nLaunching attack...", end=" ", flush=True)

    n = [r.n for r in rsa]
    ns = n[0] * n[1] * n[2]
    ms = [n[1]*n[2], n[0]*n[2], n[0]*n[1]]

    result = sum(c[i] * ms[i] * invmod(ms[i], n[i]) for i in range(3)) % ns
    root = S(result) ** Rational(1,3)
    assert root.is_integer
    pt_recovered = int(root)
    assert pt_recovered ** 3 == result
    assert pt_recovered == p

    print("Done.")
    print("Plaintext (hex):", hex(pt_recovered))
    print("Plaintext (bytes):", bytes.fromhex(hex(pt_recovered)[2:]))
