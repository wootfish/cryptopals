# text vectors from wikipedia; implementation adapted from pseudocode from same

import struct

from challenge_08 import bytes_to_chunks


def leftrotate(word: int, steps: int = 1, length: int = 32):
    return ((word << steps) | (word >> (length - steps))) & (2**length - 1)


def sha1(message: bytes) -> bytes:
    # initialize algorithm state
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    ml = 8*len(message)  # message length, in bits
    pl = 511 - ((ml - 448) % 512)  # number of zero bits to pad with

    message += b'\x80'
    message += b'\x00' * (pl//8)
    message += struct.pack(">Q", ml)
    assert len(message) % 64 == 0

    ###
    #h = message.hex()
    #while h:
    #    print(h[:8])
    #    h = h[8:]
    ###

    chunks = bytes_to_chunks(message, 64)  # 512-bit chunks
    for chunk in chunks:
        # break chunk up into 16 32-bit words, then stretch those to 80 words
        words = bytes_to_chunks(chunk, 4)
        w = [struct.unpack(">I", word)[0] for word in words] + [0]*64
        for i in range(16, 80):
            w[i] = (leftrotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]))
        assert len(w) == 80

        # initialize step state
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # main loop
        for i in range(80):
            if i < 20:
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif i < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = (
                (leftrotate(a, 5) + f + e + k + w[i]) % 2**32,
                a, leftrotate(b, 30), c, d
            )

        h0 = (h0 + a) % 2**32
        h1 = (h1 + b) % 2**32
        h2 = (h2 + c) % 2**32
        h3 = (h3 + d) % 2**32
        h4 = (h4 + e) % 2**32

    return b''.join(struct.pack(">I", h) for h in (h0, h1, h2, h3, h4))


if __name__ == "__main__":
    vec1 = sha1(b'')
    print(vec1.hex())
    print('da39a3ee5e6b4b0d3255bfef95601890afd80709')
