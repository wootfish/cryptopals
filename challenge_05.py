from challenge_02 import bytes_xor


def repeating_key_xor(key: bytes, plaintext: bytes) -> bytes:
    key_len = len(key)
    pt_len = len(plaintext)

    # expanding the key in advance like this is simple but not memory efficient
    # (good spot to optimize, if needed)
    full_key = key * (pt_len // key_len) + key[:pt_len % key_len]
    return bytes_xor(full_key, plaintext)


if __name__ == "__main__":
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    ct_expected = bytes.fromhex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    ciphertext = repeating_key_xor(b'ICE', plaintext)
    assert ciphertext == ct_expected
    print("Test passed.")
