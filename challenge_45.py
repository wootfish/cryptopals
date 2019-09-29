from challenge_39 import invmod
from challenge_43 import DSA


if __name__ == "__main__":
    DSA.g = 0
    d = DSA()

    message = b'du, du hast, du hast mich'
    print("g=0 attack:")
    print("message:", message)
    sig = d.sign(message, ignore_bad_k=True)
    print("signature:", sig)
    assert d.verify(message, sig, disable_bounds_checks=True)
    print("signature validity check passed")

    for pt in (b'ich will', b'mein herz brennt'):
        assert d.verify(pt, sig, disable_bounds_checks=True)
        print("validity check for same signature with plaintext", pt, "passed")

    print("\n----\n")

    DSA.g = DSA.p + 1  # this one relies on p+1 being congruent to 1 mod p
    d = DSA()

    z = 1
    r = pow(d.y, z, DSA.p) % DSA.q
    s = (r * invmod(z, DSA.q)) % DSA.q

    sig = (r, s)

    print("g=p+1 attack:")
    print("Magic signature:", sig)
    print("Testing signature verification.")
    for msg in (b'Hello, world', b'Goodbye, world'):
        assert d.verify(msg, sig)
        print("Verification successful for", msg)
    print("Tests complete.")
