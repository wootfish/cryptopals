from random import randrange
from os import urandom
from typing import Tuple

from Crypto.Cipher import AES

from challenge_09 import pkcs7, strip_pkcs7
from challenge_28 import sha1


INIT = "INIT"
READY = "READY"


def _enc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    return cipher.encrypt(pkcs7(plaintext))


def _dec(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    return strip_pkcs7(cipher.decrypt(ciphertext))


def trunc(s: str) -> str:
    if len(s) > 64:
        return s[:64] + "..."
    return s


class A:
    def __init__(self):
        self.state = INIT
        self.p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
        self.g = 2
        self._a = randrange(0, self.p)
        self.A = pow(self.g, self._a, self.p)
        self._s = None
        self._key = None

    def get_init_message(self) -> Tuple[int, int, int]:
        # since we're already simulating the network transfer, I decided to get
        # a bit lazy and just "simulate" data serialization too :)

        assert self.state == INIT
        message = (self.p, self.g, self.A)
        print("[A] Sending p =", trunc(hex(self.p)))
        print("            g =", trunc(hex(self.g)))
        print("            A =", trunc(hex(self.A)))
        return message

    def process_init_message(self, message: Tuple[int]):
        assert self.state == INIT
        B = message[0]
        self._s = pow(B, self._a, self.p)
        self._key = sha1(self._s.to_bytes(192, 'big'))[:16]
        self.state = READY
        print("[A] Shared secret =", trunc(hex(self._s)))
        print("    Key =", self._key.hex())

    def send(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        assert self.state == READY
        print("[A] Encrypting ", plaintext)
        iv = urandom(16)
        ct = _enc(self._key, iv, plaintext)
        return (iv, ct)

    def recv(self, message: Tuple[bytes, bytes]) -> bytes:
        assert self.state == READY
        iv, ct = message
        pt = _dec(self._key, iv, ct)
        print("[A] Decrypted  ", pt)
        return pt


class B:
    def __init__(self):
        self.state = INIT
        self.p = None
        self.g = None
        self._b = None
        self.B = None
        self._s = None
        self._key = None

    def process_init_message(self, message: Tuple[int, int, int]) -> Tuple[int]:
        # returns B's reply

        assert self.state == INIT
        self.p, self.g, A = message
        self._b = randrange(0, self.p)
        self.B = pow(self.g, self._b, self.p)

        self._s = pow(A, self._b, self.p)
        self._key = sha1(self._s.to_bytes(192, 'big'))[:16]
        self.state = READY

        print("[B] Shared secret =", trunc(hex(self._s)))
        print("    Key =", self._key.hex())
        print("    Sending B =", trunc(hex(self.B)))

        return (self.B,)

    def send(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        assert self.state == READY
        print("[B] Encrypting ", plaintext)
        iv = urandom(16)
        ct = _enc(self._key, iv, plaintext)
        return (iv, ct)

    def recv(self, message: Tuple[bytes, bytes]) -> Tuple[bytes, bytes]:
        # processes a message and returns a response
        assert self.state == READY
        iv, ct = message
        pt = _dec(self._key, iv, ct)
        print("[B] Decrypted  ", pt)
        return self.send(pt)


class M:
    def __init__(self):
        self.p = None
        self.g = None
        self.key = sha1(bytes(192))[:16]

    def tamper_init_A(self, message: Tuple[int, int, int]) -> Tuple[int, int, int]:
        self.p, self.g, _ = message
        print("[M] Tampering with A's init message")
        return (self.p, self.g, self.p)

    def tamper_init_B(self, message: Tuple[int]) -> Tuple[int]:
        print("[M] Tampering with B's init message")
        return (self.p,)

    def spy_on_message(self, message: Tuple[bytes, bytes]):
        iv, ct = message
        pt = _dec(self.key, iv, ct)
        print("[M] Intercepted", pt)
        return message


def run_without_mitm(message: bytes):
    a = A()
    b = B()

    print("Running through exchange without MITM.\n")

    a_init = a.get_init_message()
    b_init = b.process_init_message(a_init)
    a.process_init_message(b_init)

    a_msg = a.send(message)
    b_msg = b.recv(a_msg)
    a.recv(b_msg)


def run_with_mitm(message: bytes):
    a = A()
    b = B()
    m = M()

    print("Running through exchange with MITM.\n")

    a_init = a.get_init_message()
    a_init_tampered = m.tamper_init_A(a_init)

    b_init = b.process_init_message(a_init_tampered)
    b_init_tampered = m.tamper_init_B(b_init)

    a.process_init_message(b_init_tampered)

    a_msg = a.send(message)
    m.spy_on_message(a_msg)
    b_msg = b.recv(a_msg)
    m.spy_on_message(b_msg)
    a.recv(b_msg)


if __name__ == "__main__":
    run_without_mitm(b'who fuses the music with no illusions, producing the blueprints? clueless? automator - defy the laws of nature - electronic monolith, throw a jam upon a disk')
    print("\n\n----\n\n")
    run_with_mitm(b'my programming language is the strangest to come to grips with mechanized mischief')
