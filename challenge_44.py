from hashlib import sha1

from challenge_39 import invmod, InvModException
from challenge_43 import DSA, recover_x, BadKError


y = int("2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
        "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
        "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
        "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
        "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
        "2971c3de5084cce04a2e147821", base=16)
target = "ca8f6f7c66fa362d40760d135b763eb8527d3d52"


def recover_k(m1: int, m2: int, s1: int, s2: int) -> int:
    q = DSA.q
    denom = (m1 - m2) % q
    numer = (s1 - s2) % q
    return (denom * invmod(numer, q)) % q


if __name__ == "__main__":
    with open("data/44.txt", "r") as f:
        lines = f.readlines()

    msgs = []
    while lines:
        msg = {}
        msg['msg'] = lines.pop(0)[5:-1].encode("ascii")
        msg['s'] = int(lines.pop(0)[3:-1])
        msg['r'] = int(lines.pop(0)[3:-1])
        msg['m'] = int(lines.pop(0)[3:-1], base=16)
        msgs.append(msg)

    for i in range(len(msgs) - 1):
        for j in range(i+1, len(msgs)):
            msg1 = msgs[i]
            msg2 = msgs[j]
            try:
                k = recover_k(msg1['m'], msg2['m'], msg1['s'], msg2['s'])
                x1 = recover_x(msg1['r'], msg1['s'], k, msg1['m'])
                x2 = recover_x(msg1['r'], msg1['s'], k, msg1['m'])
                if x1 != x2:
                    continue
                if DSA(x=x1).sign(msg1['msg'], k=k) != (msg1['r'], msg1['s']):
                    continue
            except (InvModException, BadKError):
                continue
            x_hex = hex(x1)[2:].encode("ascii")
            print("k reuse detected for messages", i, "and", j)
            print("k =", k)
            print("x =", x1)
            print("sha1(hex(x)) =", sha1(x_hex).hexdigest())
            assert sha1(x_hex).hexdigest() == target
            print("Validity assertion passed.")
            break
        else:
            continue
        break  # break out if this loop iff we broke out of the inner loop
    else:
        print("No k reuse detected.")
