"""
Set 1, Challenge 3

Scores 
"""


from challenge_1_2 import bytes_xor


top_letters = set(ord(ch) for ch in "etoainETOAIN")


def get_candidate_score(candidate: bytes):
    score = 0
    for ch in candidate:
        if ch in top_letters:
            score += 1
    return score


def crack_xor_cipher(ciphertext: bytes):
    best_score = -1
    best_key = None
    best_plaintext = None

    l = len(ciphertext)
    for candidate_key in range(256):
        candidate_plaintext = bytes_xor(ciphertext, bytes([candidate_key]*l))
        score = get_candidate_score(candidate_plaintext)

        if score > best_score:
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
