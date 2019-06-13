import requests

from random import random
from time import sleep
from hashlib import sha256
from typing import Callable, Sequence, AnyStr
from timeit import timeit
from datetime import datetime
from multiprocessing.pool import ThreadPool

from challenge_31 import HMAC_HASH_SIZE


MAX_TRIES = 3


def crack_hmac(url: AnyStr, fname: bytes):
    def test(partial: bytes) -> None:
        sig = partial.ljust(HMAC_HASH_SIZE, bytes([0]))
        params = {'file': fname, 'signature': sig.hex()}

        times = []
        for _ in range(11):
            times.append(timeit(lambda: requests.get(url, params=params), number=1))
        times.sort()
        return times[5]


    sig = []
    tmaxes = [0]
    tries = 0
    while True:
        if len(sig) == HMAC_HASH_SIZE:
            params = {'file': fname, 'signature': bytes(sig).hex()}
            r = requests.get(url, params=params)
            if r.status_code == 200:
                break

            print("Full signature rejected. Backtracking...")
            sig.pop()
            continue

        print()
        print(datetime.now())
        print("Partial signature:", bytes(sig).hex())
        print()

        async_results = []
        times = []
        for byte in range(256):
            #f = lambda byte: (test(bytes(sig + [byte])), byte)
            #result = pool.apply_async(f, (byte,))
            #sleep(0.02 + 0.001 * len(sig))
            #async_results.append(result)
            #times.append(result.get())
            sleep(0.01)
            result = test(bytes(sig + [byte]))
            times.append((result, byte))

        #times = [result.get() for result in async_results]
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
        drest = max(times[i+1][0] - times[i][0] for i in range(len(times)-2))

        print("Deltas (first should be bigger):", dmax, drest)
        print()

        if tmax < tmaxes[-1]:
            print("tmax too low. Backtracking...")
            sig.pop()
            tmaxes.pop()
            tries = 0
            continue

        if dmax < 1.1*drest:
            if tries >= MAX_TRIES and len(sig) > 0:
                sig.pop()
                tmaxes.pop()
                tries = 0
                print("Max delta too low. Backtracking...")
            else:
                print("Max delta too low.", end="", flush=True)
                if len(sig) > 0:
                    tries += 1
                    print(" Retrying ({} of {})...".format(tries, MAX_TRIES))
                else:
                    print()
            continue

        print("New byte:", hex(times[-1][1]))
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

    sig = crack_hmac(url, fname)

    print()
    print()
    print()
    print("Done.")
    print("Filename:", fname)
    print("Final signature: ", sig.hex())
    r = requests.get(url, params={'file': fname, 'signature': sig.hex()})
    print("HTTP status code for request w/ this signature:", r.status_code)
