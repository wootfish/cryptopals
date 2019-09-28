from typing import Tuple, Optional

from challenge_03 import crack_xor_cipher


if __name__ == "__main__":
    with open("data/04.txt") as f:
        lines = [bytes.fromhex(line.strip()) for line in f]

    overall_best = (float('inf'), None, None, None)  # type: Tuple[float, Optional[int], Optional[bytes], Optional[bytes]]

    for line in lines:
        print(end='.', flush=True)
        result = crack_xor_cipher(line)
        if result[0] < overall_best[0]:
            overall_best = result + (line,)

    score, key, plaintext, ciphertext = overall_best
    print()
    print("Most likely candidate ciphertext:", ciphertext)
    print("Key:", key)
    print("Plaintext:", plaintext)
