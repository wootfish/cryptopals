def pkcs7(b: bytes, block_size: int = 16) -> bytes:
    gap_size = block_size - (len(b) % block_size)
    return b + bytes([gap_size] * gap_size)


def strip_pkcs7(b: bytes) -> bytes:
    num = b[-1]
    return b[:-num]


if __name__ == "__main__":
    plaintext = b'YELLOW SUBMARINE'
    block_size = 20
    padded = pkcs7(plaintext, block_size)
    print("Before:", plaintext)
    print("After:", padded)