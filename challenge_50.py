from Crypto.Cipher import AES

from challenge_02 import bytes_xor
from challenge_09 import pkcs7
from challenge_49 import cbc_mac

from string import digits, ascii_letters, punctuation  # can't just use printable because that includes newlines
from itertools import product


valid_chars = bytes(ord(ch) for ch in digits+ascii_letters+punctuation+' \t')

original = b"alert('MZA who was that?');\n"
substitute = b"alert('Ayo, the Wu is back!');"
target = bytes.fromhex('296b8d7cb78a243dda4d0a61d33bbdd1')

key = b'YELLOW SUBMARINE'
iv = b'\x00'*16


if __name__ == "__main__":
    assert cbc_mac(original, iv, key) == target

    # pad out the new message to block length with comment characters
    sub_len = ((len(substitute)//16)+1)*16
    sub_padded = substitute.ljust(sub_len, b'/')
    assert sub_padded.endswith(b'//')  # make sure we added at least two slashes

    # to produce a collision, we need the XOR of our attacker-controlled
    # javascript's snippet's last plaintext block with its penultimate
    # ciphertext block to equal the XOR of the same two blocks from the
    # original message. We also need the contents of the plaintext block to be
    # nothing but valid ASCII characters (i.e. 0x21 < byte val < 0x7E for each
    # byte in the plaintext).

    # first we'll find original message's XOR value
    cipher = AES.new(key, AES.MODE_CBC, iv)
    orig_padded = pkcs7(original)
    ct = cipher.encrypt(orig_padded)
    P = bytes_xor(ct[-32:-16], orig_padded[-16:])

    result = None

    # now let's search for a good ciphertext block
    for i, glue in enumerate(product(valid_chars, repeat=16)):
        if i % 100000 == 0: print(end='.', flush=True)
        glue_bytes = bytes(glue)

        # get the intermediate MAC value after this plaintext block
        ct_block = cbc_mac(sub_padded + glue_bytes, iv, key, pad=False)

        pt_block = bytes_xor(ct_block, P)
        if False in [byte in valid_chars for byte in pt_block]:
            continue

        result = sub_padded + glue_bytes + pt_block
        break

    print()

    if result is None:
        print("Search failed :(")
    else:
        print(result.decode('ascii'))  # should print: alert('Ayo, the Wu is back!');//000000000000bnS/U4lD-{)>ChwQjlMA
