from challenge_09 import strip_pkcs7, PaddingError


if __name__ == "__main__":
    assert strip_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY"

    try:
        strip_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05")
    except PaddingError:
        pass
    else:
        raise Exception("program accepted invalid padding")

    try:
        strip_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04")
    except PaddingError:
        pass
    else:
        raise Exception("program accepted invalid padding")

    print("Tests passed.")
