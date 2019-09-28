import base64


def hex_to_b64(h: str):
    return base64.b64encode(bytes.fromhex(h))


if __name__ == "__main__":
    hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    print("Before:", hex_string)

    b64_string = hex_to_b64(hex_string).decode("ascii")  # since ascii is a superset of the b64 charset
    print("After:", b64_string)

    assert b64_string == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    print("Output string's validity check passed.")
