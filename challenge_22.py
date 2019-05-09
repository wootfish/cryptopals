from challenge_21 import MT19937

from random import randint
from time import sleep, time
from itertools import count
from datetime import datetime


def rng_routine() -> int:
    #sleep(randint(40, 1000))
    sleep(randint(4, 10))  # 1000 seconds?! who has time for that?!

    t = int(time())
    r = MT19937()
    r.seed(t)

    #sleep(randint(40, 1000))
    sleep(randint(4, 10))

    return r.extract_number()


def crack_seed(output: int) -> int:
    r = MT19937()  # initialize this outside the loop to speed up the search

    # time is monotonic increasing (as far as we know) so it will be sufficient
    # to just loop down starting from an up-to-date timestamp

    for t in count(int(time()), -1):
        r.seed(t)
        if r.extract_number() == output:
            return t


if __name__ == "__main__":
    value = rng_routine()
    print("RNG output:", value)

    seed = crack_seed(value)
    print("Recovered seed:", seed, "(time: {})".format(datetime.fromtimestamp(seed)))
