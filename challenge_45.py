from challenge_39 import invmod
from challenge_43 import DSA


if __name__ == "__main__":
    #DSA.g = 0
    #d = DSA()

    #message = b'du, du hast, du hast mich'
    #print("message:", message)
    #sig = d.sign(message)
    #print("signature:", sig)

    # ^ the above code actually hangs, because my _sign() function was written
    # to request a new value of k whenever it notices r=0 or s=0 (which is
    # guaranteed to happen if we set g=0). If you temporarily disable this
    # check then the attack code works perfectly.

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
