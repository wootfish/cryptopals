def f(y, k):
    return 2 ** (y % k)


def pollard(y, a, b, k=11, g=g, p=p, quiet=True):
    # implementation of Pollard's kangaroo algorithm. Follows the description given in 58.txt

    N = 4 * (2**k - 1) // k

    if not quiet:
        print(f"Starting Pollard's algorithm (k = {k}, N = {N})")
        print()
        print("Taking the tame kangaroo out for a walk.")

    xT = 0
    yT = pow(g, b, p)
    for i in range(N):
        f_yT = f(yT, k)  # precompute this value since we use it twice
        xT += f_yT
        yT = (yT * pow(g, f_yT, p)) % p

    if not quiet: print("Releasing the wild kangaroo! (this may take a while)")

    xW = 0
    yW = y
    while xW < b - a + xT:
        f_yW = f(yW, k)
        xW += f_yW
        yW = (yW * pow(g, f_yW, p)) % p

        if yW == yT:
            if not quiet: print("The wild kangaroo found something!")
            return b + xT - xW

    print("Didn't find anything this time...")  # the algorithm is probabilistic so this may happen


if __name__ == "__main__":
    print("challenge_58.py: this script is meant to be imported, not executed!")
    print("(you're probably looking for challenge_58.ipynb)")
