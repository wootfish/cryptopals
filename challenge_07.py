import base64

from Crypto.Cipher import AES


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


if __name__ == "__main__":
    with open("data/07.txt") as f:
        b64 = f.read()

    ciphertext = base64.b64decode(b64)
    plaintext = aes_ecb_decrypt(b'YELLOW SUBMARINE', ciphertext)

    print(plaintext.decode('ascii'))  # will show 4 trailing garbage bytes at the end from block padding
