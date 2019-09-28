from base64 import b64decode
from os import urandom
from collections import Counter
from typing import List

from challenge_02 import bytes_xor
from challenge_03 import get_candidate_score
from challenge_18 import aes_ctr_enc


# addendum: i didn't read ahead & accidentally did challenge 20 here too. oops


_key = urandom(16)
texts = [aes_ctr_enc(_key, b64decode(s)) for s in (
    "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==", "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=", "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==", "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=", "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk", "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=", "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=", "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl", "VG8gcGxlYXNlIGEgY29tcGFuaW9u", "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==", "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=", "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==", "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=", "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=", "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==", "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==", "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==", "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==", "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==", "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==", "U2hlIHJvZGUgdG8gaGFycmllcnM/", "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=", "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=", "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=", "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=", "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==", "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==", "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=", "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==", "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu", "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=", "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs", "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=", "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0", "SW4gdGhlIGNhc3VhbCBjb21lZHk7", "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=", "VHJhbnNmb3JtZWQgdXR0ZXJseTo=", "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
)]


def guess_keystream(ciphertexts: List[bytes]) -> bytes:
    keystream_len = max(len(text) for text in ciphertexts)
    byte_vals = []
    for i in range(keystream_len):
        # i'th byte of each ciphertext long enough to have such a byte:
        ct_bytes = b''.join(bytes([text[i]]) for text in ciphertexts if i<len(text))
        concat_len = len(ct_bytes)

        best_score = float('inf')
        best_byte = None
        for j in range(256):
            guess = bytes_xor(ct_bytes, bytes([j]*concat_len))
            score = get_candidate_score(guess)
            if score < best_score:
                best_score = score
                best_byte = j
        assert best_byte is not None
        byte_vals.append(best_byte)
    return bytes(byte_vals)


if __name__ == "__main__":
    c = Counter(len(text) for text in texts)
    print("Ciphertext length counts:", c)
    print("Number of plaintexts of max len:", c[max(c)])

    keystream_guessed = guess_keystream(texts)
    print("Guessed keystream:", keystream_guessed)
    print("Candidate plaintexts:")

    for text in texts:
        print(bytes_xor(text, keystream_guessed))

    # the automation is not quite perfect (and indeed it can't be, because
    # there are some keystream bytes for which we only have n=1 samples to work
    # from) but we recover enough of the plaintext to recognize this as Yeats.
    # It looks to be the first two stanzas of "Easter, 1916".

    # Once we figure out the source text, it is of course trivial to obtain
    # full plaintexts and derive the keystream from them. The results of this
    # are shown below.

    longest_plaintext = b'he, too, has been changed in his turn,'
    longest_ciphertext = texts[-3]
    keystream_deduced = bytes_xor(longest_plaintext, longest_ciphertext)

    print()
    print("==================")
    print("deduced plaintext:")
    print()

    for text in texts:
        print(bytes_xor(text, keystream_deduced).decode("ascii"))
