import requests

from time import sleep
from hashlib import sha256
from typing import Callable, AnyStr, List
from timeit import timeit

from multiprocessing.pool import ThreadPool


HMAC_HASH_SIZE = 32
MAX_TRIES = 2


def do_sha256(preimage: bytes) -> bytes:
    h = sha256()
    h.update(preimage)
    return h.digest()


def hmac(key: bytes, message: bytes, h: Callable[[bytes], bytes] = do_sha256,
         h_size: int = HMAC_HASH_SIZE) -> bytes:

    if len(key) > h_size:
        key = h(key)
    else:
        key = key.ljust(h_size, b'\x00')

    key_opad = bytes(b ^ 0x5c for b in key)
    key_ipad = bytes(b ^ 0x36 for b in key)

    return h(key_opad + h(key_ipad + message))


def crack_hmac(url: AnyStr, fname: bytes):
    def test(partial: bytes) -> float:
        sig = partial.ljust(HMAC_HASH_SIZE, bytes([0]))
        params = {'file': fname, 'signature': sig.hex().encode('ascii')}
        return timeit(lambda: requests.get(url, params=params), number=1)

    pool = ThreadPool(256)  # for making lots of concurrent GET requests

    sig = []  # type: List[int]
    tmaxes = [0]  # type: List[float]
    tries = 0
    while True:
        if len(sig) == HMAC_HASH_SIZE:
            params = {'file': fname, 'signature': bytes(sig).hex().encode('ascii')}
            r = requests.get(url, params=params)
            if r.status_code == 200:
                break

            print("Full signature rejected. Backtracking...")
            sig.pop()
            continue

        print()
        print("Partial signature:", bytes(sig).hex())
        print()

        async_results = []
        for byte in range(256):
            result = pool.apply_async(
                    lambda byte: (test(bytes(sig + [byte])), byte),
                    (byte,))
            sleep(0.02 + 0.0017 * len(sig))
            async_results.append(result)

        times = [result.get() for result in async_results]
        times.sort()

        tmin = times[0][0]
        tmed = times[128][0]  # technically not QUITE the median since times[127] and times[128] are equally close to the middle. but fuck it
        tpen = times[-2][0]
        tmax = times[-1][0]

        print()
        print("Minimum time:    ", tmin)
        print("Median time:     ", tmed)
        print("Penultimate time:", tpen)
        print("Maximum time:    ", tmax)

        # in theory the difference between the max value and the penultimate
        # value should be (significantly) larger than the difference between
        # each other pair of adjacent values. backtrack if this is not the case

        # tmax should also be monotonically increasing with each iteration of
        # this loop (excluding backtracks) so we might as well enforce that too

        dmax = tmax - tpen
        drest = 0  # type: float
        for i in range(len(times) - 2):
            drest = max(drest, times[i+1][0] - times[i][0])

        print("Deltas (first should be bigger):", dmax, drest)
        print()

        if tmax < tmaxes[-1]:
            print("tmax too low. Backtracking...")
            sig.pop()
            tmaxes.pop()
            tries = 0
            continue

        if dmax < 1.25 * drest:
            if tries >= MAX_TRIES and len(sig) > 0:
                sig.pop()
                tmaxes.pop()
                tries = 0
                print("Max delta too low. Backtracking...")
            else:
                tries += 1
                print("Max delta too low. Retrying ({} of {})...".format(tries, MAX_TRIES))
            continue

        sig.append(times[-1][1])
        tmaxes.append(tmax)
        tries = 0
        sleep(0.17)  # take a breather

    return bytes(sig)


if __name__ == "__main__":
    URL = "http://localhost:5000/test"
    FNAME = "the_36th_chamber_of_shaolin.mkv"

    url = input("URL [{}]: ".format(URL)) or URL
    fname = input("Filename [{}]: ".format(FNAME)) or FNAME

    sig = crack_hmac(url.encode("ascii"), fname.encode("ascii"))

    print()
    print()
    print()
    print("Done.")
    print("Filename:", fname)
    print("Final signature: ", sig.hex())
    r = requests.get(url, params={'file': fname, 'signature': sig.hex()})
    print("HTTP status code for request w/ this signature:", r.status_code)
