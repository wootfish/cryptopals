import random


# NOTE: I believe this to be a faithful implementation of the Wikipedia
# pseudocode for the Twister; however, I have yet to find any test vectors
# which match its output.


class MersenneError(Exception): pass


class MT19937:
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908B0DF

    u, d = 11, 0xFFFFFFFF
    s, b = 7,  0x9D2C5680
    t, c = 15, 0xEFC60000

    l = 18

    f = 1812433253

    int_mask = 0xFFFFFFFF

    index = n+1  # index > n indicates rng is uninitialized

    lower_mask = 0x7FFFFFFF
    upper_mask = 0x80000000

    def __init__(self) -> None:
        self.state = [0]*self.n

    def seed(self, seed_value: int) -> None:
        self.index = self.n  # twist the state array on next call to extract_number

        self.state[0] = seed_value & self.int_mask
        for i in range(1, self.n):
            ugly_part = self.state[i-1] ^ (self.state[i-1] >> 30)
            self.state[i] = (self.f * ugly_part + i) & self.int_mask

    def extract_number(self) -> int:
        if self.index >= self.n:
            if self.index > self.n:
                raise MersenneError("Generator not yet seeded")
            self.twist()

        y = self.state[self.index]
        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= y >> self.l

        self.index += 1
        return y & self.int_mask

    def twist(self) -> None:
        for i in range(self.n):
            x = (self.state[i] & self.upper_mask) + (self.state[(i+1)%self.n] & self.lower_mask)
            xA = x >> 1
            if x & 1:
                xA ^= self.a
            self.state[i] = self.state[(i+1)%self.n] ^ xA
        self.index = 0


if __name__ == "__main__":
    r = MT19937()
    r.seed(0)  # or whatever
    print("Sample values (0 seed):")
    print(r.extract_number())
    print(r.extract_number())
    print(r.extract_number())
    print(r.extract_number())
    print(r.extract_number())
    print(r.extract_number())
    print(r.extract_number())
    print(r.extract_number())
    print(r.extract_number())
    print(r.extract_number())
