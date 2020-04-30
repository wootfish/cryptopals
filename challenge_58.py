from itertools import count
from math import log

from challenge_39 import invmod
from challenge_57 import bob, crt, get_residues, primegen


p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
q = 335062023296420808191071248367701059461
j = 34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357


def f(y, k):
    return 2 ** (y % k)


def pollard(y, a, b, k=11, g=g, p=p, quiet=True):
    # implementation of Pollard's kangaroo algorithm. May return None (since the
    # algorithm is probabilistic)

    xT = 0
    yT = pow(g, b, p)

    N = 4 * (2**k - 1) // k

    if not quiet: print(f"Starting Pollard's algorithm (k = {k}, N = {N})")
    if not quiet: print("Taking the tame kangaroo out for a walk.")
    for i in range(N):
        f_yT = f(yT, k)  # precompute this value since we use it twice
        xT += f_yT
        yT = (yT * pow(g, f_yT, p)) % p  # TODO can/should we speed this up?

    xW = 0
    yW = y

    if not quiet: print("Releasing the wild kangaroo!")
    while xW < b - a + xT:
        f_yW = f(yW, k)
        xW += f_yW
        yW = (yW * pow(g, f_yW, p)) % p

        if yW == yT:
            if not quiet: print("The wild kangaroo found something!")
            return b + xT - xW

    print("Didn't find anything this time...")


def crack_y1():
    y_1 = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119
    a_1, b_1 = 0, 2**20

    print("Trying y_1...\n")
    print("\nDone!", pollard(y_1, a_1, b_1, quiet=False))


def crack_y2():
    y_2 = 9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733
    a_2, b_2 = 0, 2**40

    print("\n\nTrying y_2... (this will take a couple minutes)\n")
    print("\nDone!", pollard(y_2, a_2, b_2, k=23, quiet=False))


def crack_dh():
    print("Launching subgroup + kangaroo attack on Diffie-Hellman.")
    print(end="Partially factoring j...", flush=True)
    j_factors = [p for p in primegen(up_to=2**16)
                 if j % p == 0 and (j // p) % p != 0]  # avoid repeated factors
    print(" done.")
    print("Some small, non-repeated factors of j:", j_factors)

    print("Initializing Bob.")
    b = bob(p=p, q=q, g=g)
    y = next(b)

    print("Extracting residues from Bob. (😏)")
    residues = get_residues(b, j_factors, p=p, quiet=False)

    print()
    print("Constraining Bob's private key using the CRT.")
    n, r = crt(residues, j_factors)
    print("x = n mod r")
    print(f"  = {n} mod {r}")
    print(f"  = {n} + m*{r}")
    print()

    g_prime = pow(g, r, p)
    print("g' = g ^ r")
    print("   =", g_prime)
    print()

    g_inv = invmod(g, p)
    y_prime = (y * pow(g_inv, n, p)) % p
    print("y' = y * g^-n")
    print("   =", y_prime)
    print("   = (g') ^ m")
    print()
    print("Finding m...")

    a, b = 0, (q - 1) // r
    print(f"Range: [{a}, 2**{log(b, 2) :.3f}]")

    for k in count(21, 2):  # only use odd values of k (b/c f's base is 2)
        print()
        m = pollard(y_prime, a, b, k, g_prime, p, quiet=False)
        if m is not None:
            break

    print("Done! m =", m)
    print("x = n + m*r =", n + m*r)

def main():
    crack_y1()
    crack_y2()
    print("\n---- later ----\n")
    crack_dh()


if __name__ == "__main__":
    main()
