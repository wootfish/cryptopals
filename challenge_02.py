"""
Set 1, Challenge 2
"""


def bytes_xor(a: bytes, b: bytes) -> bytes:
    return b''.join(
        bytes([byte_1 ^ byte_2])
        for byte_1, byte_2 in zip(a, b)
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        sys.exit("Usage: python3 challenge_02.py hex morehex")

    try:
        a = bytes.fromhex(sys.argv[1])
        b = bytes.fromhex(sys.argv[2])
    except ValueError:
        sys.exit("Error. Hex input may be malformed. Please try again.")

    result = bytes_xor(a, b)
    print(result.hex())
