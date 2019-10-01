from itertools import product, islice
from typing import Tuple, Sequence

from challenge_08 import bytes_to_chunks
from challenge_09 import pkcs7
from challenge_52 import C, MD, H_INITIAL, M_BLOCK_SIZE


# reference: https://www.schneier.com/academic/paperfiles/paper-preimages.pdf


EXPANDABLE_MSG = Sequence[Tuple[bytes, bytes]]


def make_vocal_track() -> bytes:
    vocal_loop = 'around the world'  # len = 16 chars
    vocal_track = ''
    for t in product((False, True), repeat=16):
        vocal_track += ''.join(ch.upper() if bit else ch for ch, bit in zip(vocal_loop, t))
    return vocal_track.encode('ascii')


k = 20
vocal_track = make_vocal_track()
assert 2**k == len(vocal_track)

#vocal_track = b'around the world'*2**16
# ^ Uncomment if you want to see how the attack handles a more repetitive
# input. The main difference is the bridge block search takes longer, because
# the message's intermediate H values get stuck in a cycle of length 589 --
# much fewer than the 64637 H values seen when processing the default message.


DUMMY_BLOCK = b'\xAA' * M_BLOCK_SIZE

def long_message_attack() -> bytes:
    print("\n[*] Making expandable message.")
    C, H_exp = make_expandable_message()

    print("\n[*] Looking for link block.")
    M_link, j = find_link(H_exp)

    print(f"\n[*] Link found (j = {j}).")
    print("\n[*] Generating message for second-preimage collision...")
    M_blocks = bytes_to_chunks(vocal_track, M_BLOCK_SIZE)
    M_star = produce_message(C, j)
    second_preimage = M_star + M_link + b''.join(M_blocks[j+1:])
    return second_preimage


def make_expandable_message() -> Tuple[EXPANDABLE_MSG, bytes]:
    H = H_INITIAL
    blocks = []

    for i in range(k):
        #print(f"i: {' ' if i < 10 else ''}{i}/{k-1}  ", end='')
        m_0, m_1, H = find_collision(2**i + 1, H)
        #print()
        blocks.append((m_0, m_1))

    return blocks, H


def find_collision(big_size: int, H: bytes) -> Tuple[bytes, bytes, bytes]:
    #print("Finding collision pair for message sizes 1,", big_size)
    #print("Generating intermediate state for long messages...", end='', flush=True)
    H_penult = hash_dummy_blocks(H, big_size-1)

    #print("Building corpus of short messages...")
    short_messages = {}
    for b in islice(product(range(256), repeat=M_BLOCK_SIZE), 2**13):
        M = bytes(b)
        short_messages[C(M, H)] = M

    #print("Searching through long messages...")
    for b in product(range(256), repeat=M_BLOCK_SIZE):
        M = bytes(b)
        H_next = C(M, H_penult)

        if H_next in short_messages:
            # we can just return M instead of init_blocks+M because the way we
            # store these values lets us reconstruct init_blocks as needed
            return short_messages[H_next], M, H_next

    raise Exception("no collision found :(")  # should be impossible, per pigeonhole principle


def hash_dummy_blocks(H: bytes, num_blocks: int) -> bytes:
    for i in range(num_blocks):
        if i & 0xFFFF == 0:
            print(end='.', flush=True)
        H = C(DUMMY_BLOCK, H)
    return H


def find_link(H_exp: bytes) -> Tuple[bytes, int]:
    # break down our repeating string to the message block size
    blocks = bytes_to_chunks(vocal_track, M_BLOCK_SIZE)
    len_blocks = len(blocks)

    # precompute message states to speed up the search
    H = H_INITIAL
    message_states = []
    for i in range(2**k):
        H = C(blocks[i % len_blocks], H)
        message_states.append(H)

    # search through possible link blocks until we find one that works
    for b in product(range(256), repeat=M_BLOCK_SIZE):
        M_link = bytes(b)
        H_link = C(M_link, H_exp)

        if H_link in message_states:
            ind = message_states.index(H_link)
            if ind > k:
                return M_link, ind

    raise Exception("No link block found :(")


def produce_message(C: EXPANDABLE_MSG, L: int) -> bytes:
    assert k <= L <= 2**k + k - 1
    T = L - k
    S = bin(T)[:1:-1].ljust(k, '0')
    M = b''
    for i, bit in enumerate(S):
        if bit == '0':
            M += C[i][0]
        else:
            dummies = DUMMY_BLOCK * 2**i
            M += dummies + C[i][1]
    return M


if __name__ == "__main__":
    print(f"\n[*] Message (len={len(vocal_track)}): {vocal_track[:1000].decode('ascii')}...")
    print("\n[*] Starting attack.")

    second_preimage = long_message_attack()
    assert len(vocal_track) == len(second_preimage)

    hash_1 = MD(vocal_track)
    hash_2 = MD(second_preimage)
    assert hash_1 == hash_2

    print(f"\n[*] Attack complete. len(second_preimage) = {len(second_preimage)}")
    print(f"\nMD({vocal_track[:80]}...{vocal_track[-40:]}) = {hash_1}")
    print(f"\nMD({second_preimage[:25]}...{second_preimage[-40:]}) = {hash_2}")
    print()
