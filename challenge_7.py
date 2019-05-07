# depends on library pycrypto


from Crypto.Cipher import AES


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


if __name__ == "__main__":
    import sys
    import base64
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 1_7.py filename")

    with open(sys.argv[1]) as f:
        b64 = f.read()
    ciphertext = base64.b64decode(b64)
    plaintext = aes_ecb_decrypt(b'YELLOW SUBMARINE', ciphertext)

    print(plaintext.decode('ascii'))  # will show 4 trailing garbage bytes at the end from block padding
