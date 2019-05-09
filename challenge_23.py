from challenge_21 import MT19937

from os import urandom
from typing import Generator


def untemper(y: int) -> int:
    # undo xors number 3 & 4 (easy)
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000

    # undo xor number 2 (tricky)
    # (there must be a better way, but this is more fun without google)
    block = y & 0x7F
    inverted = block
    for i in range(1, 5):
        block = (block & (0x9D2C5680 >> (7*i))) ^ (y >> (7*i)) & 0x7F
        inverted += block << (7*i)
    y = inverted

    # undo xor number 1 (same ideas as 2 but shifting the other way, and
    # written differently because variety is the spice of life)
    block1 = y & 0xFFE00000
    block2 = (y ^ (block1 >> 11)) & 0x001FFC00
    block3 = (y ^ (block2 >> 11)) & 0x000003FF
    y = block1 + block2 + block3

    return y


def clone(rng: MT19937) -> MT19937:
    outputs = [rng.extract_number() for _ in range(624)]
    state = [untemper(val) for val in outputs]

    new_rng = MT19937()
    new_rng.index = new_rng.n  # initialize
    new_rng.state = state

    return new_rng


if __name__ == "__main__":
    for _ in range(10):
        r1 = MT19937()
        r1.seed(int.from_bytes(urandom(8), 'big'))
        r2 = clone(r1)

        assert r2 is not r1
        assert r2.state is not r1.state
        assert r2.state == r1.state
        for _ in range(10**5):
            assert r1.extract_number() == r2.extract_number()
        print(".", end="", flush=True)

    print("Tests passed.")
