from Crypto.Cipher import Blowfish  # allows smaller block & key sizes than AES

from challenge_08 import bytes_to_chunks
from challenge_09 import pkcs7

from itertools import count, product


M_BLOCK_SIZE = 8
H_SIZE = 4
H_INITIAL = b'\x00'*H_SIZE


def C(M_i, H):
    # assumptions: len(M_i) == M_BLOCK_SIZE, len(H) == H_SIZE
    cipher = Blowfish.new(H, Blowfish.MODE_ECB)  # note: we do take a performance hit here (AES sets up faster than Blowfish)
    return cipher.encrypt(M_i)[:H_SIZE]


def MD(M, H=H_INITIAL, C=C):
    blocks = bytes_to_chunks(pkcs7(M, M_BLOCK_SIZE), M_BLOCK_SIZE)
    for block in blocks:
        H = C(block, H)
    return H


if __name__ == "__main__":
    print(f"State size: {len(H_INITIAL)*8} bits")
    print("Finding collisions...\n")

    colliding_blocks = []
    H = H_INITIAL
    for i in count(1):
        outputs = {}
        for j, candidate in enumerate(product(range(256), repeat=M_BLOCK_SIZE)):
            #if j % 10000 == 0: print(end=".", flush=True)
            m1 = bytes(candidate)
            out = C(m1, H)
            if out in outputs:
                m2 = outputs[out]
                colliding_blocks.append((m1, m2))
                H = out
                break
            outputs[out] = m1
        else:
            raise Exception("no collisions found?!")  # should be impossible, per pigeonhole principle

        for comb in product((0, 1), repeat=i):
            preimage = b''.join(colliding_blocks[j][comb[j]] for j in range(i))
            print(f"MD(bytes.fromhex('{preimage.hex()}')) = {MD(preimage)}")
        print("Total collisions:", 2**i)
        print()
