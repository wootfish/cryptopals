from challenge_09 import strip_pkcs7, PaddingError


def test():
    assert strip_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY"

    try:
        strip_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05")
    except PaddingError:
        pass
    else:
        assert False  # failed to raise exception

    try:
        strip_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04")
    except PaddingError:
        pass
    else:
        assert False  # failed to raise exception



if __name__ == "__main__":
    test()

    import sys
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 challenge_15.py padded")
    print(strip_pkcs7(sys.argv[1].encode("ascii")))
