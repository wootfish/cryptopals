from os import urandom
from random import choice, randrange, sample

from hashlib import sha256

from challenge_31 import hmac


N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
I = b"eli@sohl.com"


class Server:
    def __init__(self, password):
        self.P = password
        self.salt = urandom(32)
        self.b = randrange(0, N)
        xH = sha256(self.salt + self.P).digest()
        x = int.from_bytes(xH, 'big')
        self.v = pow(g, x, N)
        print("[S] Initialized with password", password)

    def auth_1(self, message):
        _I, A = message
        assert _I == I
        B = pow(g, self.b, N)

        # precompute u, S, K
        self.u = int.from_bytes(urandom(16), 'big')
        S = pow(A * pow(self.v, self.u, N), self.b, N)
        self.K = sha256(S.to_bytes(192, 'big')).digest()

        print("[S] K =", self.K.hex())
        return (self.salt, B, self.u)

    def auth_2(self, message):
        hmac_attempt = message[0]
        if hmac_attempt == hmac(self.K, self.salt):
            print("[S] Client authentication accepted.")
            return ("OK",)
        print("[S] Client authentication rejected.")
        return ("not today buddy",)


class Client:
    def __init__(self, password):
        self.a = randrange(0, N)
        self.P = password
        print("[C] Initialized with password", password)

    def auth_1(self):
        self.A = pow(g, self.a, N)
        return (I, self.A)

    def auth_2(self, message):
        salt, B, u = message

        xH = sha256(salt + self.P).digest()
        x = int.from_bytes(xH, 'big')
        S = pow(B, self.a + u*x, N)
        K = sha256(S.to_bytes(192, 'big')).digest()

        print("[C] K =", K.hex())

        return (hmac(K, salt),)

    def auth_3(self, message):
        assert message == ("OK",)
        print("[C] *hacker voice* I'M IN.")


if __name__ == "__main__":
    with open("/usr/share/dict/words") as f:
        lines = [line.strip().encode("utf-8") for line in f]
    dictionary = sample(lines, 10000)  # limit dictionary size to 10k (just for convenience's sake)
    _password = choice(dictionary)

    print("[*] Running through normal exchange for simplified SRP...")
    c = Client(_password)
    s = Server(_password)

    client_1 = c.auth_1()
    server_1 = s.auth_1(client_1)
    client_2 = c.auth_2(server_1)
    server_2 = s.auth_2(client_2)
    c.auth_3(server_2)

    print("\n\n[*] Simulating attack against client...")
    b = randrange(0, N)
    B = pow(g, b, N)
    u = int.from_bytes(urandom(16), 'big')
    salt = urandom(32)

    c = Client(_password)
    _, A = c.auth_1()
    c_hmac = c.auth_2((salt, B, u))[0]

    print("[*] HMAC captured. Launching dictionary attack...", end="", flush=True)
    i = 0
    for guess in dictionary:
        i += 1
        if i % 500 == 0:
            print(".", end="", flush=True)

        xH = sha256(salt + guess).digest()
        x = int.from_bytes(xH, 'big')
        v = pow(g, x, N)
        S = pow(A * pow(v, u, N), b, N)
        K = sha256(S.to_bytes(192, 'big')).digest()

        s_hmac = hmac(K, salt)
        if s_hmac == c_hmac:
            break

    print()
    if s_hmac == c_hmac:
        print("[*] Dictionary attack successful. Password:", guess)
    else:
        print("[*] Dictionary attack failed (?!)")
