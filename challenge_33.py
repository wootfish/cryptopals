from random import randrange


if __name__ == "__main__":
    print("\nRunning through toy example.")
    p = 37
    g = 5

    print(f"p, g = {p}, {g}")

    a = randrange(0, 37)
    A = pow(g, a, p)
    print(f"a, A = {a}, {A}")

    b = randrange(0, 37)
    B = pow(g, b, p)
    print(f"b, B = {b}, {B}")

    s1 = pow(A, b, p)
    s2 = pow(B, a, p)
    print("Secrets:", s1, s2)
    assert s1 == s2
    print("Equality assertion passed.")

    ####################

    print("\n\nRunning through bignum example.")
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    print(f"p, g = {p}, {g}")

    a = randrange(0, p)
    A = pow(g, a, p)
    print(f"a, A = {a}, {A}")

    b = randrange(0, p)
    B = pow(g, b, p)
    print(f"b, B = {b}, {B}")

    s1 = pow(A, b, p)
    s2 = pow(B, a, p)
    print("Secrets:", s1, s2)
    assert s1 == s2
    print("Equality assertion passed.\n")
