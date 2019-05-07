"""
Set 1, Challenge 3

Scores 
"""


from challenge_1_3 import crack_xor_cipher


if __name__ == "__main__":
    with open("data/1_4.txt") as f:
        lines = [bytes.fromhex(line.strip()) for line in f]

    overall_best = (-1, None, None, None)

    for line in lines:
        result = crack_xor_cipher(line)
        if result[0] > overall_best[0]:
            overall_best = result + (line,)

    score, key, plaintext, ciphertext = overall_best
    print("Most likely candidate ciphertext:", ciphertext)
    print("Key:", key)
    print("Plaintext:", plaintext)
