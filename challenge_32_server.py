# usage (from containing folder)
# bash: FLASK_APP=challenge_31_server.py flask run
# fish: env FLASK_APP=challenge_31_server.py flask run

from time import sleep
from os import urandom
from urllib.parse import unquote

from flask import Flask, request, abort

from challenge_31 import hmac


app = Flask(__name__)
_key = urandom(32)

print("Actual signature:", hmac(_key, b'the_36th_chamber_of_shaolin.mkv').hex())


def insecure_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b): return False
    for byte1, byte2 in zip(a, b):
        if byte1 != byte2:
            return False
        sleep(0.005)  # 5 ms
    return True


@app.route("/test", methods=["GET"])
def test():
    fname = request.args.get("file").encode("ascii")
    hmac_claimed = bytes.fromhex(request.args.get("signature"))
    hmac_actual = hmac(_key, fname)

    if insecure_compare(hmac_claimed, hmac_actual):
        return "i'll allow it"
    abort(500)
