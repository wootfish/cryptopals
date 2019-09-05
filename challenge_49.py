from os import urandom

from Crypto.Cipher import AES

from challenge_02 import bytes_xor
from challenge_09 import pkcs7


class BadMacError(Exception): pass


ALICE_ID = 1
BOB_ID = 2
MALLORY_ID = 3


def cbc_mac(message, iv, key, pad=True):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    if pad: message = pkcs7(message)
    return cipher.encrypt(message)[-16:]


_K = urandom(16)
def api_query_1(message, iv, mac):
    if cbc_mac(message, iv, _K) != mac:
        raise BadMacError
    print("MAC validated.")

    kvs = [term.split(b"=") for term in message.split(b"&")]
    args = {key: value for key, value in kvs}
    src = args[b'from']
    dst = args[b'to']
    amt = args[b'amount']
    print(f"Transaction processed: {amt} from user {src} to user {dst}")


def api_query_2(message, mac):
    if cbc_mac(message, b'\x00'*16, _K) != mac:
        raise BadMacError
    print("MAC validated.")

    kvs = [term.split(b"=") for term in message.split(b"&")]
    args = {key: value for key, value in kvs}
    src = args[b'from']
    txns = args[b'tx_list'].split(b';')
    for entry in txns:
        dst, amt = entry.split(b':')
        print(f"Transaction processed: {amt} from user {src} to user {dst}")


def make_txn_1(src, dst, amt):
    message = f"from={src}&to={dst}&amount={amt}".encode()
    iv = urandom(16)
    mac = cbc_mac(message, iv, _K)
    return message, iv, mac


def make_txn_2(src, dst, amt):
    message = f"from={src}&tx_list={dst}:{amt}".encode()
    mac = cbc_mac(message, b'\x00'*16, _K)
    return message, mac


def chosen_iv_attack(msg, iv, mac):
    offset = len(f"from={ALICE_ID}&to=")
    delta = bytes([0]*offset + [ord(str(BOB_ID)) ^ ord(str(MALLORY_ID))])
    new_iv = bytes_xor(iv, delta.ljust(16, b'\x00'))
    new_msg = bytes_xor(msg, delta.ljust(len(msg), b'\x00'))
    return new_msg, new_iv, mac


def length_extension_attack(msg, mac):
    # note that this attack requires the ability to generate a tag for a
    # carefully constructed second message
    padded = pkcs7(msg)
    suffix = f';{MALLORY_ID}:000;{MALLORY_ID}:{10**6}'.encode()  # includes a txn for $000 to pad out the block length
    new_mac = cbc_mac(suffix, mac, _K)
    new_msg = padded + suffix
    return new_msg, new_mac


if __name__ == "__main__":
    print("==== Chosen-IV attack")
    print("[*] Alice (user 1) sending $1M to Bob (user 2).")
    txn = make_txn_1(ALICE_ID, BOB_ID, 10**6)
    api_query_1(*txn)

    print("\n[*] Mallory (user 3) forging $1M transfer to herself from Alice.")  # hey, nice, this attack passes the Bechdel test
    api_query_1(*chosen_iv_attack(*txn))

    print("\n\n==== Length-extension attack")
    print("[*] Alice sending $34 to Bob.")
    txn = make_txn_2(ALICE_ID, BOB_ID, 34)
    api_query_2(*txn)

    print("\n[*] Mallory appending a $1M transfer to herself.")
    api_query_2(*length_extension_attack(*txn))
