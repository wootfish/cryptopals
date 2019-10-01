from hashlib import sha256

from challenge_31 import hmac
from challenge_36 import Client, Server, I, N


# simulating the network interaction, like with challenge 34 et al


if __name__ == "__main__":
    print("[*] Running through normal SRP exchange...")
    c = Client()
    s = Server()

    client_msg_1 = c.auth_1()
    server_msg_1 = s.auth_1(client_msg_1)
    client_msg_2 = c.auth_2(server_msg_1)
    server_msg_2 = s.auth_2(client_msg_2)
    c.auth_3(server_msg_2)

    print()

    # these values don't actually change within the loop since all the values
    # of A used are congruent to 0 mod N
    S = 0
    K = sha256(S.to_bytes(192, 'big')).digest()

    for i in range(4):
        s = Server()
        print("\n[*] Trying attack with A = {}*N".format(i))
        try:
            A = i*N
            client_1 = (I, A)
            salt, _ = s.auth_1(client_1)
            salt_hmac = hmac(K, salt)

            print("[C] Sending HMAC =", salt_hmac)
            result = s.auth_2((salt_hmac,))

            if result == ("OK",):
                print("[C] Accepted!")
            else:
                print("[C] Rejected (?!)")

        except OverflowError:
            print("[*] Value of A rejected by server (too large).")

        print()
