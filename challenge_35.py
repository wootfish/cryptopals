from challenge_03 import get_candidate_score
from challenge_09 import pkcs7, strip_pkcs7
from challenge_28 import sha1
from random import randrange
from os import urandom

from Crypto.Cipher import AES


# These attacks tamper with g and A, in contrast with challenge 34, where we
# tampered with A and B.
#
# The tricky bit here is, there's a gotcha with the (p-1) attack. If a is even
# and b is odd then Alice and Bob will end up with different shared secrets.
# This can be easy to miss because it only happens with (appx) probability
# 0.25. The solution is:
#
# * figure out the parity of b from B
# * figure out the parity of A by trial decryption on the first ciphertext
# * figure out Alice and Bob's keys from this information
# * actively translate each ciphertext from the sender's key to the receiver's
#
# this solves the issue when it arises; the rest of the time, it's pretty much
# just a no-op.


INIT_1 = "INIT_1"
INIT_2 = "INIT_2"
INIT_3 = "INIT_3"
READY = "READY"


MODE_ONE = "1"
MODE_ZERO = "p"
MODE_NEG1 = "p-1"


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
        self.state = INIT_1
        self.p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
        self.g = 2
        self.a = randrange(0, self.p)
        self.A = pow(self.g, self.a, self.p)
        self.s = None
        self.key = None

    def get_init_message_1(self):
        assert self.state == INIT_1
        message = (self.p, self.g)
        self.state = INIT_2
        print("[A] Sending p =", trunc(hex(self.p)))
        print("            g =", trunc(hex(self.g)))
        return message

    def get_init_message_2(self, ack):
        assert self.state == INIT_2
        assert ack == ("ACK",)
        message = (self.A,)
        self.state = INIT_3
        print("[A] Received ACK.")
        print("    Sending A =", trunc(hex(self.A)))
        return message

    def process_init_message_2(self, message):
        assert self.state == INIT_3
        B = message[0]
        self.s = pow(B, self.a, self.p)
        self.key = sha1(self.s.to_bytes(192, 'big'))[:16]
        self.state = READY
        print("[A] Shared secret =", trunc(hex(self.s)))
        print("    Key =", self.key.hex())

    def send(self, plaintext):
        assert self.state == READY
        print("[A] Encrypting ", plaintext)
        iv = urandom(16)
        ct = _enc(self.key, iv, plaintext)
        return (iv, ct)

    def recv(self, message):
        assert self.state == READY
        iv, ct = message
        pt = _dec(self.key, iv, ct)
        print("[A] Decrypted  ", pt)
        return pt


class B:
    def __init__(self):
        self.state = INIT_1
        self.p = None
        self.g = None
        self.b = None
        self.B = None
        self.s = None
        self.key = None

    def process_init_message_1(self, message):
        assert self.state == INIT_1
        self.p, self.g = message
        self.b = randrange(0, self.p)
        self.B = pow(self.g, self.b, self.p)
        self.state = INIT_2
        print("[B] Received p =", trunc(hex(self.p)))
        print("             g =", trunc(hex(self.g)))
        print("    Sending ACK.")
        return ("ACK",)

    def process_init_message_2(self, message):
        assert self.state == INIT_2
        A = message[0]
        self.s = pow(A, self.b, self.p)
        self.key = sha1(self.s.to_bytes(192, 'big'))[:16]
        self.state = READY
        print("[B] Received A =", trunc(hex(A)))
        print("    Shared secret =", trunc(hex(self.s)))
        print("    Key =", self.key.hex())
        print("[B] Sending B =", trunc(hex(self.B)))
        return (self.B,)

    def send(self, plaintext):
        assert self.state == READY
        print("[B] Encrypting ", plaintext)
        iv = urandom(16)
        ct = _enc(self.key, iv, plaintext)
        return (iv, ct)

    def recv(self, message):
        assert self.state == READY
        iv, ct = message
        pt = _dec(self.key, iv, ct)
        print("[B] Decrypted  ", pt)
        return self.send(pt)


class M:
    def __init__(self, mode):
        self.p = None
        self.mode = mode

        if mode == MODE_ONE:
            self.a_key = self.b_key = sha1((1).to_bytes(192, 'big'))[:16]
        elif mode == MODE_ZERO:
            self.a_key = self.b_key = sha1(bytes(192))[:16]
        elif self.mode == MODE_NEG1:
            self.a_key = self.b_key = None

    def get_new_g(self):
        if self.mode == MODE_ONE:
            return 1
        elif self.mode == MODE_ZERO:
            return self.p
        elif self.mode == MODE_NEG1:
            return self.p - 1
        raise Exception("mode not recognized")

    def tamper_init_1_A(self, message):
        self.p = message[0]  # we don't care about A's g value
        print("[M] Tampering with A's first init message (new g value: {})".format(self.mode))
        return (self.p, self.get_new_g())

    def snoop_init_2_B(self, message):
        if self.mode == MODE_NEG1:
            # if message == (p-1) then b is even; else the shared secret depends on A
            if message == (self.p-1,):
                self.b_key = sha1((self.p-1).to_bytes(192, 'big'))[:16]

    def tamper_init_2_A(self, message):
        print("[M] Tampering with A's second init message (new A value: {})".format(self.mode))
        return (self.get_new_g(),)

    def spy_on_message(self, message, a_or_b):
        iv, ct = message

        if self.mode == MODE_NEG1 and a_or_b == "A":
            if self.a_key == None:
                # secret could either be 1 or -1 mod p
                key1 = sha1((1).to_bytes(192, 'big'))[:16]
                key2 = sha1((self.p-1).to_bytes(192, 'big'))[:16]

                # the incorrect key will almost certainly produce a message with
                # invalid padding; test for that using try blocks, and use ascii
                # character frequency as a fallback test

                try: score1 = get_candidate_score(_dec(key1, iv, ct))
                except: score1 = float('inf')

                try: score2 = get_candidate_score(_dec(key2, iv, ct))
                except: score2 = float('inf')

                print("[M] Candidate key scores:", score1, score2)
                self.a_key = key1 if score1 < score2 else key2

            if self.b_key == None:
                # key was determined to depend on A
                self.b_key = self.a_key

        key_dec = self.a_key if a_or_b == "A" else self.b_key
        key_enc = self.a_key if a_or_b == "B" else self.b_key
        print("[M] Inferred keys: key_a, key_b =", self.a_key.hex(), self.b_key.hex())
        pt = _dec(key_dec, iv, ct)
        print("    Intercepted", pt)
        ct_2 = _enc(key_enc, iv, pt)
        if key_dec == key_enc: assert ct == ct_2
        message = (iv, ct_2)

        return message


def run_without_mitm(message):
    a = A()
    b = B()

    print("Running through exchange without MITM.\n")

    a_init_1 = a.get_init_message_1()
    b_init_1 = b.process_init_message_1(a_init_1)
    a_init_2 = a.get_init_message_2(b_init_1)
    b_init_2 = b.process_init_message_2(a_init_2)
    a.process_init_message_2(b_init_2)

    a_msg = a.send(message)
    b_msg = b.recv(a_msg)
    a.recv(b_msg)


def run_with_mitm(message):
    print("Running through exchanges with MITM.\n")

    for mode in (MODE_ONE, MODE_ZERO, MODE_NEG1):
        print("\n\nMode: g =", mode, "\n\n")

        a = A()
        b = B()
        m = M(mode)

        a_init_1 = a.get_init_message_1()
        a_init_1 = m.tamper_init_1_A(a_init_1)  # replace first init w/ tampered version
        b_init_1 = b.process_init_message_1(a_init_1)

        a_init_2 = a.get_init_message_2(b_init_1)
        a_init_2 = m.tamper_init_2_A(a_init_2)  # replace second init w/ tampered version

        b_init_2 = b.process_init_message_2(a_init_2)
        m.snoop_init_2_B(b_init_2)
        a.process_init_message_2(b_init_2)

        a_msg = a.send(message)
        a_msg = m.spy_on_message(a_msg, "A")

        b_msg = b.recv(a_msg)
        b_msg = m.spy_on_message(b_msg, "B")

        a.recv(b_msg)

        #a_init = a.get_init_message_1()
        #a_init_tampered = m.tamper_init_1_A(a_init)

        #b_init = b.process_init_message_1(a_init_tampered)
        #a.process_init_message(b_init)

        #a_msg = a.send(a_message)
        #m.spy_on_message(a_msg)
        #b_msg = b.recv(a_msg)
        #m.spy_on_message(b_msg)
        #a.recv(b_msg)


if __name__ == "__main__":
    run_without_mitm(
            b'who fuses the music with no illusions, producing the blueprints? clueless? automator - defy the laws of nature - electronic monolith, throw a jam upon a disk'
            )
    print("\n\n----\n\n")
    run_with_mitm(
            b'my programming language is the strangest to come to grips with mechanized mischief'
            )
