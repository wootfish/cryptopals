from challenge_02 import bytes_xor
from typing import Dict


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


def hamming_distance(a: bytes, b: bytes) -> int:
    # the hamming distance between two bytestrings is equal to the hamming
    # weight of their xor
    return sum(weights[byte] for byte in bytes_xor(a, b))

