from challenge_09 import pkcs7, strip_pkcs7
from challenge_28 import sha1
from random import randrange
from os import urandom

from Crypto.Cipher import AES


INIT = "INIT"
READY = "READY"


def _enc(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    return cipher.encrypt(pkcs7(plaintext))


def _dec(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    return strip_pkcs7(cipher.decrypt(ciphertext))


def trunc(s):
    if len(s) > 64:
        return s[:64] + "..."
    return s


class A:
    def __init__(self):
        self.state = INIT
        self.p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
        self.g = 2
        self.a = randrange(0, self.p)
        self.A = pow(self.g, self.a, self.p)
        self.s = None
        self.key = None

    def get_init_message(self):
        # since we're already simulating the network transfer, I decided to get lazy
        # and just simulate data serialization, too :)

        assert self.state == INIT
        message = (self.p, self.g, self.A)
        print("[A] Sending p =", trunc(hex(self.p)))
        print("            g =", trunc(hex(self.g)))
        print("            a =", trunc(hex(self.a)))
        return message

    def process_init_message(self, message):
        assert self.state == INIT
        B = message[0]
        self.s = pow(B, self.a, self.p)
        self.key = sha1(self.s.to_bytes(192, 'big'))[:16]
        self.state = READY
        print("[A] Shared secret =", trunc(hex(self.s)))
        print("    Key =", self.key.hex())

    def send(self, plaintext):
        assert self.state == READY
        print("[A] Encrypting", plaintext)
        iv = urandom(16)
        ct = _enc(self.key, iv, plaintext)
        return (iv, ct)

    def recv(self, message):
        assert self.state == READY
        iv, ct = message
        pt = _dec(self.key, iv, ct)
        print("[A] Decrypted", pt)
        return pt


class B:
    def __init__(self):
        self.state = INIT
        self.p = None
        self.g = None
        self.b = None
        self.B = None
        self.s = None
        self.key = None

    def process_init_message(self, message):
        # returns B's reply

        assert self.state == INIT
        self.p, self.g, A = message
        self.b = randrange(0, self.p)
        self.B = pow(self.g, self.b, self.p)

        self.s = pow(A, self.b, self.p)
        self.key = sha1(self.s.to_bytes(192, 'big'))[:16]
        self.state = READY

        print("[B] Shared secret =", trunc(hex(self.s)))
        print("    Key =", self.key.hex())
        print("[B] Sending B =", trunc(hex(self.B)))

        return (self.B,)

    def send(self, plaintext):
        assert self.state == READY
        print("[B] Encrypting", plaintext)
        iv = urandom(16)
        ct = _enc(self.key, iv, plaintext)
        return (iv, ct)

    def recv(self, message):
        assert self.state == READY
        iv, ct = message
        pt = _dec(self.key, iv, ct)
        print("[B] Decrypted", pt)
        return pt


class M:
    def __init__(self):
        self.p = None
        self.g = None
        self.key = sha1(bytes(192))[:16]

    def tamper_init_A(self, message):
        self.p, self.g, _ = message
        print()
        print("[M] Tampering with A's init message")
        print()
        return (self.p, self.g, self.p)

    def tamper_init_B(self, message):
        print()
        print("[M] Tampering with B's init message")
        print()
        return (self.p,)

    def spy_on_message(self, message):
        iv, ct = message
        pt = _dec(self.key, iv, ct)
        print()
        print("[M] Intercepted message:", pt)
        print()
        return message


def run_without_mitm(a_message, b_message):
    a = A()
    b = B()

    print("Running through exchange without MITM.\n")

    a_init = a.get_init_message()
    b_init = b.process_init_message(a_init)
    a.process_init_message(b_init)

    a_msg = a.send(a_message)
    b.recv(a_msg)

    b_msg = b.send(b_message)
    a.recv(b_msg)


def run_with_mitm(a_message, b_message):
    a = A()
    b = B()
    m = M()

    print("Running through exchange with MITM.\n")

    a_init = a.get_init_message()
    a_init_tampered = m.tamper_init_A(a_init)

    b_init = b.process_init_message(a_init_tampered)
    b_init_tampered = m.tamper_init_B(b_init)

    a.process_init_message(b_init_tampered)

    a_msg = a.send(a_message)
    m.spy_on_message(a_msg)
    b.recv(a_msg)

    b_msg = b.send(b_message)
    m.spy_on_message(b_msg)
    a.recv(b_msg)


if __name__ == "__main__":
    run_without_mitm(
            b'who fuses the music with no illusion, producing the blueprints? clueless?',
            b'automator - defy the laws of nature - electronic monolith, throw a jam upon a disk'
            )
    print("\n\n----\n\n")
    run_with_mitm(
            b'my programming language is the strangest to come to grips with mechanized mischief',
            b'kick it off with circular projectiles, x-files, heralded as the most important, dwarf the corporate'
            )
