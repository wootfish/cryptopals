from challenge_39 import invmod
from challenge_43 import DSA


if __name__ == "__main__":
    #DSA.g = 0
    #d = DSA()

    #message = b'du, du hast, du hast mich'
    #print("message:", message)
    #sig = d.sign(message)
    #print("signature:", sig)

    # ^ the above code actually hangs, because the _sign() function requests a
    # new value of k whenever it notices r=0 or s=0 (which happens
    # unconditionally when we set g=0)

    DSA.g = DSA.p + 1  # p+1 is congruent to 1 mod p, of course
    d = DSA()

    z = 1
    r = pow(d.y, z, DSA.p) % DSA.q
    s = (r * invmod(z, DSA.q)) % DSA.q

    sig = (r, s)

    print("Magic signature:", sig)
    print("Testing signature verification.")
    for msg in (b'Hello, world', b'Goodbye, world'):
        assert d.verify(msg, sig)
        print("Verification successful for", msg)
    print("Tests complete.")
