"""
Set 1, Challenge 6
"""


import base64

from itertools import combinations
from pprint import pprint
from typing import List, Tuple, Dict

from challenge_02 import bytes_xor
from challenge_03 import crack_xor_cipher
from challenge_05 import repeating_key_xor


def hamming_distance(a: bytes, b: bytes) -> int:
    # the hamming distance between two bytestrings is equal to the hamming
    # weight of their xor
    return sum(weights[byte] for byte in bytes_xor(a, b))


def get_hamming_weights() -> Dict[int, int]:
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


MAX_KEYSIZE = 40
def guess_keysize(ct: bytes, guesses: int = 1) -> List[Tuple[float, int]]:
    def get_score(size: int) -> int:
        chunks = (ct[:size],
                  ct[size:2*size],
                  ct[2*size:3*size],
                  ct[3*size:4*size])
        avg = sum(hamming_distance(a,b) for a,b in combinations(chunks, 2)) / 12
        return avg / size

    scores = [(get_score(size), size) for size in range(1, MAX_KEYSIZE+1)]
    scores.sort()
    return scores[:guesses]


def crack_repeating_key_xor(ciphertext: bytes, keysize: int) -> Tuple[float, bytes]:
    """
    Requires key size. Returns confidence score and key (not plaintext).
    """

    chunks = [ciphertext[i::keysize] for i in range(keysize)]
    cracks = [crack_xor_cipher(chunk) for chunk in chunks]

    combined_score = sum(t[0] for t in cracks) / keysize
    key = bytes(t[1] for t in cracks)
    return combined_score, key


if __name__ == "__main__":
    assert hamming_distance(b'this is a test', b'wokka wokka!!!') == 37

    with open("data/06.txt") as f:
        b64 = f.read()
    ciphertext = base64.b64decode(b64)

    keysizes = guess_keysize(ciphertext, 5)
    print("Key size guesses (confidence, size):")
    pprint(keysizes)
    print()

    candidates = [crack_repeating_key_xor(ciphertext, guess) for score, guess in keysizes]
    candidates.sort()
    top_key = candidates[0][1]

    print("Top guess:")
    print("key =", top_key)
    print("plaintext =\n")
    print(repeating_key_xor(top_key, ciphertext).decode("ascii"))
