from challenge_08 import bytes_to_chunks
from challenge_09 import pkcs7
from challenge_52 import C, MD, H_INITIAL, M_BLOCK_SIZE

from itertools import product, islice

from os import urandom


# reference: https://www.schneier.com/academic/paperfiles/paper-preimages.pdf


def make_vocal_track():
    vocal_loop = 'around the world'  # len = 16 chars
    vocal_track = ''
    for t in product((False, True), repeat=16):
        vocal_track += ''.join(ch.upper() if bit else ch for ch, bit in zip(vocal_loop, t))
    return vocal_track.encode('ascii')


k = 20
vocal_track = make_vocal_track()
assert 2**k == len(vocal_track)


def long_message_attack():
    print("\n[*] Making expandable message.")
    C, H_exp = make_expandable_message()

    print("\n[*] Looking for link block.")
    j = find_link(H_exp)

    print(f"\n[*] Link found (j = {j}). Generating message for second-preimage collision...")
    M_blocks = bytes_to_chunks(vocal_track, M_BLOCK_SIZE)
    M_star = produce_message(C, j-1)
    second_preimage = M_star + b''.join(M_blocks[j:])
    return second_preimage


def make_expandable_message():
    H = H_INITIAL
    blocks = []

    for i in range(k):
        #print(f"i: {' ' if i < 10 else ''}{i}/{k-1}  ", end='')
        m_0, m_1, H = find_collision(2**i + 1, H)
        #print()
        blocks.append((m_0, m_1))
    print()
    return blocks, H


def find_collision(big_size, H):
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

    raise Exception("no collision found :(")  # should be impossible, per pigeonhole


DUMMY_BLOCK = b'\x00' * M_BLOCK_SIZE
def hash_dummy_blocks(H, num_blocks):
    for i in range(num_blocks):
        if i & 0xFFFF == 0:
            print(end='.', flush=True)
        H = C(DUMMY_BLOCK, H)
    return H


def find_link(H_exp):
    # break down our repeating string to the message block size
    blocks = bytes_to_chunks(vocal_track, M_BLOCK_SIZE)
    len_blocks = len(blocks)  # precomputing this speeds up the loop

    # search through intermediate states until we find a link
    print(2**k - k, "blocks to search.")
    H = H_INITIAL
    s = set()
    for i in range(2**k):
        #if i & 0x1FFFF == 0:
        #    print(end='.', flush=True)
        H = C(blocks[i%len_blocks], H)
        s.add(H)
        if i >= k and H == H_exp:
            return i

    print("# of distinct blocks seen:", len(s))
    raise Exception("No link block found :(")


def produce_message(C, L):
    assert k <= L <= 2**k + k - 1
    T = L - k
    S = bin(T)[:2:-1]  # [:2:-1] reverses string & leaves off first 2 bytes ('0x')
    M = b''.join(C[i][0 if bit == '0' else 1] for i, bit in enumerate(S))
    return M


if __name__ == "__main__":
    #message = vocal_loop * 2**k
    print()
    print(f"[*] Message (len={len(vocal_track)}): {vocal_track[:1000].decode('ascii')}...")
    print()
    print("[*] Starting attack.")
    second_preimage = long_message_attack()
    print()
    print("[*] Attack complete.")
    print(f"len(second_preimage) = {len(second_preimage)}")
    print()
    print(f"MD({vocal_track[:32]}...{vocal_track[-32:]}) = {MD(vocal_track)}")
    print(f"MD({second_preimage[:32]}...{second_preimage[-32:]}) = {MD(second_preimage)}")
