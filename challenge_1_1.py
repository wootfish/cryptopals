"""
Set 1, Challenge 1
"""


import base64


def hex_to_b64(h: str) -> bytes:
    return base64.b64encode(bytes.fromhex(h))


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 1_1.py hex")

    hex_bytes = sys.argv[1]

    try:
        b64 = hex_to_b64(hex_bytes)
    except ValueError:
        sys.exit("Error. Hex input may be malformed. Please try again.")

    print(b64.decode("ascii"))  # since ascii is a superset of the b64 charset
