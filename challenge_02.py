"""
Set 1, Challenge 2
"""


def _bytes_xor(a: bytes, b: bytes) -> bytes:
    return b''.join(
        bytes([byte_1 ^ byte_2])
        for byte_1, byte_2 in zip(a, b)
    )


def bytes_xor(*args: bytes, quiet=True) -> bytes:
    assert len(args) > 0
    result = args[0]
    for arg in args[1:]:
        if not quiet: print(result, arg)
        result = _bytes_xor(result, arg)
    return result


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
