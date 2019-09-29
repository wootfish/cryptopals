from base64 import b64decode

from math import ceil, log

from challenge_39 import RSA


rsa = RSA()
_pt = int.from_bytes(b64decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="), 'big')
ct = rsa.enc(_pt)


def oracle(ct: int) -> bool:
    """
    Returns True for even plaintexts, False for odd ones.
    """
    return rsa.dec(ct) & 1 == 0


if __name__ == "__main__":
    e, n = rsa.pubkey

    lower = 0
    upper = n

    ct_new = ct
    coeff = rsa.enc(2)

    for i in range(ceil(log(n, 2))):
        mid = (lower + upper) // 2

        if i & 0xFF == 0:
            print("\nUpper bound:", hex(upper))
        elif i & 1 == 0:
            print(end='.', flush=True)

        ct_new = (coeff * ct_new) % n

        if oracle(ct_new):
            upper = mid
        else:
            lower = mid

    print()
    print("Oracle attack complete.")
    print("Repairing trailing bits...")

    # for some reason the least significant bytes never seem to be quite right.
    # my best guess is there's probably an off-by-one error in the search math.
    # that's a pain to debug tho, and the margin of error seems to be well less
    # than 12 bits, so hey - let's just brute force the end of the message.

    masked = upper ^ (upper & 0xFFF)  # zero out the last 12 bits

    pt = None
    for i in range(2**12):
        if rsa.enc(masked + i) == ct:
            pt = masked + i
            break

    pt_bytes = (pt or upper).to_bytes(ceil(log(n, 2))//8, 'big').lstrip(b'\x00')
    if pt is None:
        print("Repair failed. Best approximation of plaintext:", pt_bytes)
    else:
        print("Repair complete. Plaintext:", pt_bytes)
