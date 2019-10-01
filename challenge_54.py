from os import urandom
from itertools import product
from typing import Generator, List, Tuple, Set

from challenge_52 import C, MD, MD_PAD, H_SIZE, M_BLOCK_SIZE


k = 6

predictions = [
        b"The Mariners are going all the way. ",  # lol i wish
        b"It's gonna be the Red Sox.          ",
        b"uh... idk, like, the fucken Cubs?   "
        ]


def all_blocks(block_size=M_BLOCK_SIZE) -> Generator[bytes, None, None]:
    # how has it taken me this long to think of writing this helper?!
    for b in product(range(256), repeat=block_size):
        yield bytes(b)


def get_initial_states(k=k) -> List[bytes]:
    states = set()  # type: Set[bytes]
    for _ in range(2**k):
        s = urandom(H_SIZE)
        while s in states:
            s = urandom(H_SIZE)
        states.add(s)
    return list(states)


def get_hash(H: bytes, M_len: int) -> bytes:
    assert M_len % M_BLOCK_SIZE == 0  # keep things from getting messy
    dummy = b' ' * (M_len + M_BLOCK_SIZE*(k+1))  # +1 b/c of the glue block
    padding = MD_PAD(dummy)[len(dummy):]
    return MD(padding, H=H, pad=False)


def find_collision(H_1: bytes, H_2: bytes) -> Tuple[bytes, bytes]:
    for M in all_blocks():
        C_1 = C(M, H_1)
        C_2 = C(M, H_2)
        if C_1 == C_2:
            return M, C_1
    raise Exception("ruh roh")


if __name__ == "__main__":
    states = get_initial_states()
    state_tree = []

    print("Initial states generated.")

    while len(states) > 1:
        print(f"\nlen(states) = {len(states)}")
        state_map = {}
        new_states = []
        for i in range(0, len(states), 2):
            print(end='.', flush=True)
            H_1 = states[i]
            H_2 = states[i+1]
            M, H_3 = find_collision(H_1, H_2)
            state_map[H_1] = (M, H_3)
            state_map[H_2] = (M, H_3)
            new_states.append(H_3)
        state_tree.append(state_map)
        states = new_states
        print()

    print("Done precomputing.")
    print("Here's the hash of my prophecy:", get_hash(states[0], 36))
    print("\n------\n")
    print("Generating messages for hash...\n")

    for message in predictions:
        H = MD(message, pad=False)

        for glue in all_blocks():
            H_new = C(glue, H)
            if H_new in state_tree[0]:
                message += glue
                break

        for layer in state_tree:
            M, H_new = layer[H_new]
            message += M

        print("Prediction:", message)
        print("Hashes to", MD(message))
        print()
