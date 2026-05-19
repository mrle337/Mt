import hmac
import hashlib
import os
import requests
from flask import Flask, request, Response

app = Flask(__name__)

PROXY_SECRET = bytes.fromhex(os.environ["PROXY_SECRET_HEX"])
KEYAUTH_URL  = "https://keyauth.win/api/1.3/"
TIMEOUT_SEC  = 15

@app.route("/api/1.3/", methods=["POST"])
def proxy():
    try:
        upstream = requests.post(
            KEYAUTH_URL,
            data=request.get_data(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent":   "KeyAuth/1.3",
            },
            timeout=TIMEOUT_SEC,
        )
    except requests.RequestException:
        return Response("upstream unreachable", status=502)

    body = upstream.content
    sig  = hmac.new(PROXY_SECRET, body, hashlib.sha256).hexdigest()

    resp = Response(body, status=upstream.status_code)
    resp.headers["Content-Type"] = upstream.headers.get(
        "Content-Type", "application/json")
    resp.headers["signature"] = sig
    return resp

@app.route("/healthz")
def healthz():
    return "ok"