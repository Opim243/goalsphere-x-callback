import os
import base64
import hashlib
import secrets
from urllib.parse import urlencode

import requests
from flask import Flask, request, redirect

app = Flask(__name__)

CLIENT_ID = os.environ.get("X_CLIENT_ID")
CLIENT_SECRET = os.environ.get("X_CLIENT_SECRET")

REDIRECT_URI = "https://goalsphere-x-callback.onrender.com/callback"

AUTH_URL = "https://twitter.com/i/oauth2/authorize"
TOKEN_URL = "https://api.x.com/2/oauth2/token"
POST_URL = "https://api.x.com/2/tweets"

SCOPES = "tweet.read tweet.write users.read offline.access"

oauth_data = {}


def create_pkce():
    verifier = secrets.token_urlsafe(64)

    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()

    return verifier, challenge


@app.route("/")
def home():
    return "Goal Sphere X Callback is running."


@app.route("/login")
def login():
    verifier, challenge = create_pkce()
    state = secrets.token_urlsafe(32)

    oauth_data["state"] = state
    oauth_data["verifier"] = verifier

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    return redirect(AUTH_URL + "?" + urlencode(params))


@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if not code:
        return {
            "error": request.args.get("error"),
            "message": "Aucun code OAuth reçu"
        }, 400

    if state != oauth_data.get("state"):
        return {
            "error": "invalid_state",
            "message": "Le state OAuth ne correspond pas."
        }, 400

    verifier = oauth_data.get("verifier")

    response = requests.post(
        TOKEN_URL,
        data={
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=30
    )

    if response.status_code != 200:
        return {
            "error": "token_exchange_failed",
            "status_code": response.status_code,
            "response": response.text
        }, 400

    token = response.json()

    oauth_data.clear()

    return {
        "message": "Authentification X réussie",
        "token_received": True,
        "scope": token.get("scope"),
        "has_refresh_token": bool(token.get("refresh_token"))
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
