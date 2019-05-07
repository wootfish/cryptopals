from challenge_1_2 import bytes_xor


def repeating_key_xor(key: bytes, plaintext: bytes) -> bytes:
    key_len = len(key)
    pt_len = len(plaintext)

    # expanding the key in advance like this is simple but not memory efficient
    # (good spot to optimize down the road, if need be)
    full_key = key * (pt_len // key_len) + key[:pt_len % key_len]
    return bytes_xor(full_key, plaintext)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 1_5.py plaintext")

    plaintext = sys.argv[1].encode("UTF-8")  # ascii would probably be fine too, but... u never kno
    ciphertext = repeating_key_xor(b'ICE', plaintext)
    print(ciphertext.hex())
