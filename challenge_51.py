from Crypto.Cipher import AES

from zlib import compress
from os import urandom
from string import ascii_letters, digits

from challenge_09 import pkcs7


_sessionid = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
b64_chars = ascii_letters + digits + '+/='


def _format_request(P):
    return f"""POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid={_sessionid}
Content-Length: {len(P)}
{P}""".encode('ascii')


def oracle(P: str, stream=True) -> int:
    request = _format_request(P)
    compressed = compress(request)
    mode = AES.MODE_CFB if stream else AES.MODE_CBC
    cipher = AES.new(urandom(16), mode, urandom(16))
    ciphertext = cipher.encrypt(compressed if stream else pkcs7(compressed))
    return len(ciphertext)


def attack_cfb_mode() -> str:
    prefix = "Cookie: sessionid="
    recovered = ""
    while not recovered.endswith("="):
        part = (prefix + recovered)[-17:]
        candidates = [(oracle(part+ch), ch) for ch in b64_chars]
        candidates.sort()
        assert candidates[0][0] != candidates[-1][0]
        recovered += candidates[0][1]
    return recovered


def attack_cbc_mode() -> str:
    # prefix abcde to pad us out to the block size
    prefix = "abcdeCookie: sessionid="
    recovered = ""

    while not recovered.endswith("="):
        part = (prefix + recovered)
        candidates = [(oracle(part+ch1+ch2, stream=False), ch1, ch2)
                for ch1 in b64_chars for ch2 in b64_chars]
        candidates.sort()
        assert candidates[0][0] != candidates[-1][0]
        recovered += candidates[0][1] + candidates[0][2]
    return recovered


if __name__ == "__main__":
    print("[*] Recovering sessionid (cipher: AES-CFB)")
    sessionid = attack_cfb_mode()
    print("sessionid (actual):   ", _sessionid)
    print("sessionid (recovered):", sessionid)
    assert sessionid == _sessionid
    print("Equality assertion passed.\n")

    print("[*] Recovering sessionid (cipher: AES-CBC)")
    sessionid = attack_cbc_mode()
    print("sessionid (actual):   ", _sessionid)
    print("sessionid (recovered):", sessionid)
    assert sessionid == _sessionid
    print("Equality assertion passed.\n")
