from Crypto.Cipher import ARC4

from itertools import count
from random import getrandbits
from base64 import b64decode


# takes a while to run, since each step requires (at least) 2**26 ciphertexts


_secret = b64decode("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F")  # 30 bytes


def get_enc_oracle(chosen_message):
    pt = chosen_message + _secret
    def oracle():
        key = getrandbits(128).to_bytes(16, 'big')
        c = ARC4.new(key)
        return c.encrypt(pt)
    return oracle


def summarize(counter, size):
    top = sorted(((count, byte) for byte, count in enumerate(counter)), reverse=True)[:2]
    probabilities = [(val, count / size) for count, val in top]
    return probabilities


def check(top_2, quiet=True):
    one, two = top_2
    if not quiet: print(one, two, '|', abs(one[1] - 0.00375), 0.97*one[1], ">", two[1])
    return abs(one[1] - 0.00375) < 0.00034 and 0.996*one[1] > two[1]


def recover_bytes(offset, sample_size=2**26):
    # returns plaintext bytes at indices 15 and 31
    INTERVAL_SIZE = 0xFFFFF
    ind_15 = [0] * 256
    ind_31 = [0] * 256
    zeroes = bytes(offset)
    oracle = get_enc_oracle(zeroes)

    for i in range(sample_size):
        if i & INTERVAL_SIZE == 0:
            print(end='.', flush=True)
        ct = oracle()
        ind_15[ct[15]] += 1
        ind_31[ct[31]] += 1

    summary_1 = summarize(ind_15, sample_size)
    summary_2 = summarize(ind_31, sample_size)

    while not (check(summary_1) and check(summary_2)):
        print(end=',', flush=True)
        for j in range(INTERVAL_SIZE):
            ct = oracle()
            ind_15[ct[15]] += 1
            ind_31[ct[31]] += 1
        sample_size += INTERVAL_SIZE
        summary_1 = summarize(ind_15, sample_size)
        summary_2 = summarize(ind_31, sample_size)

    print()
    return summary_1[0][0] ^ 240, summary_2[0][0] ^ 224


if __name__ == "__main__":
    plaintext = [0] * 30

    print(len(_secret))
    print(len(plaintext))

    for i in range(16):
        print("Intermediate plaintext:", bytes(plaintext))
        m1, m2 = recover_bytes(i+2)
        if 13-i >= 0:
            plaintext[13-i] = m1
        plaintext[29-i] = m2

    print("Final recovered plaintext:", bytes(plaintext))
