from hashlib import sha256
from math import log, ceil

from sympy import S, Rational  # type: ignore

from challenge_39 import RSA as RSA_39


class RSA(RSA_39):
    ASN1_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")  # this hex is from https://tools.ietf.org/html/rfc3447#section-9.2

    def _EMSA_PKCS1_v1_5_SHA256(self, M: bytes) -> bytes:
        k = ceil(log(self.n, 2**8))  # no need to pass k in, since we can just compute it here
        b = sha256(M).digest()
        b = b'\x00' + self.ASN1_SHA256 + b
        b = b.rjust(k-2, b'\xFF')
        b = b'\x00\x01' + b
        return b

    def sign(self, message: bytes) -> int:
        em = self._EMSA_PKCS1_v1_5_SHA256(message)
        m = int.from_bytes(em, 'big')
        return self.dec(m)

    def check_sig(self, message: bytes, sig: int) -> bool:
        em = self._EMSA_PKCS1_v1_5_SHA256(message)
        m = int.from_bytes(em, 'big')
        m2 = self.enc(sig)
        return m == m2

    def check_sig_broken(self, message: bytes, sig: int) -> bool:
        k = ceil(log(self.n, 2**8))

        m = self.enc(sig)
        em = m.to_bytes(k, 'big')

        if not em.startswith(b'\x00\x01\xFF\xFF'): return False
        if b'\xFF\x00' not in em: return False
        em = em[em.index(b'\xFF\x00')+2:]   # skip over the bulk of the padding bytes without validating them

        if not em.startswith(self.ASN1_SHA256): return False
        em = em[len(self.ASN1_SHA256):]
        em = em[:32]  # just the hash, not anything after

        return em == sha256(message).digest()


if __name__ == "__main__":
    message = b'hi mom'

    print("Generating RSA keypair.")
    r = RSA()
    print("Public key:", r.pubkey)
    print()

    print("Testing signature primitives.")
    s = r.sign(b'what up')
    assert r.check_sig(b'what up', s)
    print("First signature check passed.")
    assert r.check_sig_broken(b'what up', s)
    print("Second signature check passed.")
    print()

    orig = r._EMSA_PKCS1_v1_5_SHA256(message)
    end_len = 32 + len(r.ASN1_SHA256) + 2
    trimmed = orig[:4] + orig[-end_len:]
    size = len(orig) - len(trimmed)

    print("Forging valid signature for message:", message)
    m = int.from_bytes(trimmed + b'\x00'*size, 'big')
    sig = int(S(m) ** Rational(1, 3)) + 1

    print("Signature forged:", hex(sig))
    print("Validity check (sane, expect False):", r.check_sig(message, sig))
    print("Validity check (broken, expect True):", r.check_sig_broken(message, sig))
