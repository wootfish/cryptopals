"""
Set 1, Challenge 3

Note: There's a subtle reason why the get_candidate_score function below only
counts lowercase letters. You might think you'd get better results from
counting uppercase letters as well. However, there is a quirk of ASCII that we
have to account for: each ASCII letter's lowercase and uppercase forms differ
by exactly one bit. As a consequence, for any XOR cipher key producing
lowercase text there is a key differing by precisely one bit which will produce
the same plaintext but with inverted case (and with almost all punctuation
replaced by garbage characters). If lowercase and uppercase letters are
weighted equally, these related keys are equally likely to be discovered.

There are a number of hacks that could get around this:

    * Check the relative frequencies of lowercase and uppercase text in your
      output, flip the appropriate key bit(s) if uppercase outnumbers lowercase.
    * Add in frequency counts for punctuation, as most punctuation characters
      become corrupted by this bit-flip.
    * Skip some candidate plaintexts using a blacklist of some or all non-ASCII
      characters (could improve performance, at the cost of misinterpreting any
      weird plaintexts)
    * Create adjusted frequency counts for uppercase letters and score based on
      these.
    * Assume the bulk of your ciphertexts' body text will be lowercase and opt
      to just ignore uppercase letters entirely (figuring the error terms the
      text's uppercase letters add to each lowercase letter's frequency counts
      will be roughly equal, meaning the relative frequencies of lowercase
      letters shouldn't be thrown too far off).

All of these involve some degree of compromise. Since none are perfect, I just
chose the one that seemed simplest: ignoring uppercase completely.
"""


from challenge_2 import bytes_xor
from typing import Tuple


# derived from http://practicalcryptography.com/media/cryptanalysis/files/english_monograms.txt
frequencies = {'a': 0.0855, 'b': 0.0160, 'c': 0.0316, 'd': 0.0387, 'e': 0.1209,
               'f': 0.0218, 'g': 0.0209, 'h': 0.0496, 'i': 0.0732, 'j': 0.0022,
               'k': 0.0081, 'l': 0.0420, 'm': 0.0253, 'n': 0.0717, 'o': 0.0747,
               'p': 0.0206, 'q': 0.0010, 'r': 0.0633, 's': 0.0673, 't': 0.0894,
               'u': 0.0268, 'v': 0.0106, 'w': 0.0182, 'x': 0.0019, 'y': 0.0172,
               'z': 0.0011}


def get_candidate_score(candidate: bytes) -> float:
    # lower scores are better
    score = 0
    l = len(candidate)

    for letter, frequency in frequencies.items():
        count = candidate.count(ord(letter))  # don't even worry about counting uppercase letters (see note above)
        err = abs(frequency - count / l)
        score += err

    return score


def crack_xor_cipher(ciphertext: bytes) -> Tuple[float, bytes, bytes]:
    best_score = float('inf')
    best_key = None
    best_plaintext = None

    l = len(ciphertext)
    for candidate_key in range(256):
        candidate_plaintext = bytes_xor(ciphertext, bytes([candidate_key]*l))
        score = get_candidate_score(candidate_plaintext)

        if score < best_score:
            best_score = score
            best_key = candidate_key
            best_plaintext = candidate_plaintext

    return (best_score, best_key, best_plaintext)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 1_3.py hex")

    try:
        ciphertext = bytes.fromhex(sys.argv[1])
    except ValueError:
        sys.exit("Error. Hex input may be malformed. Please try again.")

    score, key, text = crack_xor_cipher(ciphertext)
    print("Key:", key)
    print("Plaintext:", text)
