import struct

from random import choice
from itertools import count
from typing import Tuple, Callable

from challenge_28 import sha1


def get_padding(message: bytes) -> bytes:
    ml = 8*len(message)  # message length, in bits
    pl = 511 - ((ml - 448) % 512)  # number of zero bits to pad with
    padding = b'\x80'
    padding += b'\x00' * (pl//8)
    padding += struct.pack(">Q", ml)
    return padding


def forge_mac(message: bytes, mac: bytes, suffix: bytes, oracle: Callable[[bytes, bytes], bool]) -> Tuple[bytes, bytes]:
    # returns (new_message, new_mac)

    # first, get the representation of the mac as state variables
    words = mac[:4], mac[4:8], mac[8:12], mac[12:16], mac[16:]
    state = [struct.unpack(">I", word)[0] for word in words]

    # to figure out our new message's contents, we need to know the padding on
    # the original message. to figure that out, we'll need to guess the length
    # of the key. that's what this loop does.
    print("Trying key length:", end=" ", flush=True)
    for i in count(0):
        print(i, end=" ", flush=True)

        glue_padding = get_padding(b' '*i + message)
        len_with_glue = len(b' '*i + message + glue_padding) * 8  # in bits
        new_message = message + glue_padding + suffix
        new_mac = sha1(suffix, state=state, padding_offset=len_with_glue)

        if oracle(new_message, new_mac):
            print("done.")
            return (new_message, new_mac)

        if i > len(_key): raise Exception("aw fuck")  # this indicates a bug


message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'


if __name__ == "__main__":
    # pick a key and make a helper function to check MAC validity under the key
    with open("/usr/share/dict/words") as f:
        _key = choice(f.readlines()).strip().encode('ascii')

    def check_mac(message: bytes, mac: bytes) -> bool:
        return sha1(_key + message) == mac

    # this is the initial (unforged) MAC
    # (also checks the padding via an assert inside sha1())
    _preimage = _key + message
    _glue_padding = get_padding(_preimage)
    mac1 = sha1(_preimage, padding=_glue_padding)

    # ok, time to get to work
    forged, mac2 = forge_mac(message, mac1, b';admin=true', check_mac)

    print("First MAC:", mac1.hex())
    print("Forged message:", forged)
    print("Forged MAC:", mac2.hex())
    print("Validity check:", check_mac(forged, mac2))
