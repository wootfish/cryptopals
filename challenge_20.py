from base64 import b64decode
from os import urandom

from challenge_02 import bytes_xor
from challenge_18 import aes_ctr_enc
from challenge_19 import guess_keystream


key = urandom(16)


if __name__ == "__main__":
    with open("data/20.txt") as f:
        ciphertexts = [aes_ctr_enc(key, b64decode(line)) for line in f]

    ks_guess = guess_keystream(ciphertexts)

    for text in ciphertexts:
        plaintext = bytes_xor(text, ks_guess)
        print(plaintext)

    # same deal as with 19. rakim has the honor on this one

    plaintext = b"you want to hear some sounds that not only pounds but please your eardrums; / I sit back and observe the whole scenery"
    ciphertext = ciphertexts[26]
    keystream = bytes_xor(plaintext, ciphertext)

    print()
    print("-------")
    print()

    for text in ciphertexts:
        plaintext = bytes_xor(text, keystream)
        print(plaintext.decode("ascii"))
