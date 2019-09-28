from os import urandom
from random import randrange
from hashlib import sha256
from typing import Tuple

from challenge_31 import hmac


N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
I = b"eli@sohl.com"
P = b"trustno1"


class Server:
    def __init__(self):
        self.salt = urandom(32)
        self.b = randrange(0, N)
        xH = sha256(self.salt + P).digest()
        x = int.from_bytes(xH, 'big')
        self.v = pow(g, x, N)

    def auth_1(self, message: Tuple[bytes, int]) -> Tuple[bytes, int]:
        # Input:  C->S Send I, A=g**a % N (a la Diffie Hellman)
        # Output: S->C Send salt, B=kv + g**b % N

        _I, A = message
        assert _I == I
        B = (k*self.v + pow(g, self.b, N)) % N

        # precompute uH, u, S, K
        uH_preimage = A.to_bytes(192, 'big') + B.to_bytes(192, 'big')
        uH = sha256(uH_preimage).digest()

        print("[S] uH =", uH.hex())

        u = int.from_bytes(uH, 'big')
        S = pow(A * pow(self.v, u, N), self.b, N)
        self.K = sha256(S.to_bytes(192, 'big')).digest()

        print("[S] K  =", self.K.hex())

        return (self.salt, B)

    def auth_2(self, message: Tuple[bytes]) -> Tuple[str]:
        hmac_attempt = message[0]
        if hmac_attempt == hmac(self.K, self.salt):
            print("[S] Client authentication accepted.")
            return ("OK",)
        print("[S] Client authentication rejected.")
        return ("not today buddy",)


class Client:
    def __init__(self):
        self.a = randrange(0, N)

    def auth_1(self) -> Tuple[bytes, int]:
        self.A = pow(g, self.a, N)
        return (I, self.A)

    def auth_2(self, message: Tuple[bytes, int]) -> Tuple[bytes]:
        salt, B = message

        xH_preimage = salt + P
        uH_preimage = self.A.to_bytes(192, 'big') + B.to_bytes(192, 'big')

        xH = sha256(xH_preimage).digest()
        uH = sha256(uH_preimage).digest()

        print("[C] uH =", uH.hex())

        x = int.from_bytes(xH, 'big')
        u = int.from_bytes(uH, 'big')

        S = pow(B - k*pow(g, x, N), self.a + u*x, N)
        K = sha256(S.to_bytes(192, 'big')).digest()

        print("[C] K  =", K.hex())

        return (hmac(K, salt),)

    def auth_3(self, message: Tuple[str]):
        assert message == ("OK",)
        print("[C] *hacker voice* I'M IN.")


if __name__ == "__main__":
    c = Client()
    s = Server()

    client_1 = c.auth_1()
    server_1 = s.auth_1(client_1)
    client_2 = c.auth_2(server_1)
    server_2 = s.auth_2(client_2)
    c.auth_3(server_2)
