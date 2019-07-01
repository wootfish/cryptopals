from challenge_39 import RSA, invmod


if __name__ == "__main__":
    msg = b"i feel my luck could change"
    pt = int.from_bytes(msg, 'big')

    print("Initializing RSA...")
    rsa = RSA()
    ct = rsa.enc(pt)

    print("Message:", msg)
    print("Encoded:", hex(pt))
    print("Ciphertext:", hex(ct))

    s = 2
    sinv = invmod(s, rsa.n)
    ct_prime = (pow(s, rsa.e, rsa.n) * ct) % rsa.n

    print("Modified ct:", hex(ct_prime))

    pt_prime = rsa.dec(ct_prime)
    pt2 = (pt_prime * sinv) % rsa.n

    print("Modified pt:", hex(pt_prime))

    assert pt == pt2

    print("Recovered:", hex(pt2))
    print("Plaintext:", bytes.fromhex(hex(pt2)[2:]))
