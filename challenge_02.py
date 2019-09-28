"""
Set 1, Challenge 2
"""


from typing import List


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
    a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    b = bytes.fromhex("686974207468652062756c6c277320657965")
    result = bytes_xor(a, b)
    assert result == bytes.fromhex("746865206b696420646f6e277420706c6179")
    print(f"{a.hex()} XOR {b.hex()} == {result.hex()}")
