from itertools import count


def bytes_to_chunks(b: bytes, chunk_size: int):
    return [b[ind:ind+chunk_size] for ind in range(0, len(b), chunk_size)]


def score_for_ecb(ciphertext: bytes):
    # tries to score the likelihood of the ciphertext using ECB mode by
    # counting how many repeated blocks there are in the ciphertext
    # (lower score = more likely to be ECB)
    chunks = bytes_to_chunks(ciphertext, 16)
    return len(set(chunks)) / len(chunks)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 challenge_08.py filename")

    with open(sys.argv[1]) as f:
        ciphertexts = [bytes.fromhex(line.strip()) for line in f]

    best_score, best_i, best_ciphertext = float('inf'), None, None
    for i, ciphertext in enumerate(ciphertexts):
        score = score_for_ecb(ciphertext)
        if score < best_score:
            best_score = score
            best_i = i
            best_ciphertext = ciphertext

    print("Line", i, "seems most likely to be using ECB. (score: {})".format(best_score))
    print("Ciphertext:", ciphertext)