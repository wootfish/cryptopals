"""
Set 1, Challenge 6
"""


from challenge_1_2 import bytes_xor
from challenge_1_5 import repeating_key_xor
import challenge_1_3

import itertools


def get_hamming_weights():
    """
    Generates a lookup table for the hamming weight of every byte. Computing
    these on-demand is easy too, but a lookup table is faster & simpler :)
    """

    weights = {0: 0}
    pow_2 = 1
    for _ in range(8):
        for k, v in weights.copy().items():
            weights[k+pow_2] = v+1
        pow_2 <<= 1
    return weights


weights = get_hamming_weights()


def hamming_distance(a: bytes, b: bytes):
    # the hamming distance between two bytestrings is equal to the hamming
    # weight of their xor
    return sum(weights[byte] for byte in bytes_xor(a, b))


MAX_KEYSIZE_GUESS = 32  # raise this if keysize guesses aren't panning out
def guess_keysize(ciphertext: bytes, guesses: int = 1):
    max_keysize = min(MAX_KEYSIZE_GUESS, len(ciphertext) // 4)

    def get_score(size):
        chunks = (ciphertext[:size],
                  ciphertext[size:2*size],
                  ciphertext[2*size:3*size],
                  ciphertext[3*size:4*size])
        avg = sum(hamming_distance(a,b) for a,b in itertools.combinations(chunks, 2)) / 12
        return avg / size

    scores = [(get_score(size), size) for size in range(1, max_keysize+1)]
    scores.sort()
    return scores[:guesses]


def crack_repeating_key_xor(ciphertext: bytes, keysize: int):
    """
    Requires key size. Returns confidence score and key (not plaintext).
    """

    chunks = [ciphertext[i::keysize] for i in range(keysize)]
    cracks = [challenge_1_3.crack_xor_cipher(chunk) for chunk in chunks]

    combined_score = sum(score for score, _, __ in cracks) / keysize
    key = bytes(key_byte for _, key_byte, __ in cracks)
    return combined_score, key


if __name__ == "__main__":
    assert hamming_distance(b'this is a test', b'wokka wokka!!!') == 37

    import sys
    import base64

    if len(sys.argv) != 2:
        sys.exit("Usage: python3 challenge_1_6.py filename")

    with open(sys.argv[1]) as f:
        b64 = f.read()
    ciphertext = base64.b64decode(b64)

    keysizes = guess_keysize(ciphertext, 5)
    #print("Key size guesses:", keysizes)

    challenge_1_3.top_letters = set(ord(ch) for ch in "etaoinshrdluETAOINSHRDLU")  # expand set of target characters for xor cracker

    best_confidence = float('inf')
    best_guess = None

    for confidence, guess in keysizes:
        confidence, guess = crack_repeating_key_xor(ciphertext, guess)
        print(repeating_key_xor(guess, ciphertext))
        input()
