from itertools import count, product
from typing import Dict

from Crypto.Cipher import AES

from challenge_08 import bytes_to_chunks


PAD_LEN_FIELD_SIZE = 64  # same as sha1 (unlike all other params here lol)
M_BLOCK_SIZE = 4
H_SIZE = 2
H_INITIAL = b'\x00'*H_SIZE


AES_KEY_PADDING = b'\x00'*(16-H_SIZE)
AES_BLOCK_PADDING = b'\x00'*(16-M_BLOCK_SIZE)


def C(M_i: bytes, H: bytes) -> bytes:
    # assumptions: len(M_i) == M_BLOCK_SIZE, len(H) == H_SIZE
    cipher = AES.new(H+AES_KEY_PADDING, AES.MODE_ECB)
    return cipher.encrypt(M_i+AES_BLOCK_PADDING)[:H_SIZE]


def MD_PAD(msg: bytes) -> bytes:
    l = len(msg) % 2**PAD_LEN_FIELD_SIZE
    len_field = l.to_bytes(PAD_LEN_FIELD_SIZE, 'big')
    zeroes_needed = -(len(msg) + 1 + PAD_LEN_FIELD_SIZE) % M_BLOCK_SIZE
    padded = msg + b'\x01' + b'\x00'*zeroes_needed + len_field
    return padded


def MD(M: bytes, H=H_INITIAL, C=C, pad=True) -> bytes:
    if pad:
        M = MD_PAD(M)
    assert len(M) % M_BLOCK_SIZE == 0
    blocks = bytes_to_chunks(M, M_BLOCK_SIZE)
    for block in blocks:
        H = C(block, H)
    return H


if __name__ == "__main__":
    print(f"State size: {len(H_INITIAL)*8} bits")
    print("Finding collisions...\n")

    colliding_blocks = []
    H = H_INITIAL
    for i in count(1):
        outputs = {}  # type: Dict[bytes, bytes]
        for j, candidate in enumerate(product(range(256), repeat=M_BLOCK_SIZE)):
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

        expected = MD(b''.join(colliding_blocks[j][0] for j in range(i)))
        for j, prod in enumerate(product((0, 1), repeat=i)):
            preimage = b''.join(colliding_blocks[j][prod[j]] for j in range(i))
            image = MD(preimage)
            assert image == expected
            print(f"({j}/{2**i}) MD(bytes.fromhex('{preimage.hex()}')) = {image}")
