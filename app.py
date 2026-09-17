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

# Token X conservé pendant l'exécution du service Render
access_token = None
refresh_token = None


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

    authorization_url = AUTH_URL + "?" + urlencode(params)

    return redirect(authorization_url)


@app.route("/callback")
def callback():
    global access_token, refresh_token

    code = request.args.get("code")
    state = request.args.get("state")

    if not code:
        return {
            "success": False,
            "step": "authorization",
            "error": request.args.get("error"),
            "message": "Aucun code OAuth reçu."
        }, 400

    if state != oauth_data.get("state"):
        return {
            "success": False,
            "step": "state",
            "error": "invalid_state",
            "message": "Le state OAuth ne correspond pas."
        }, 400

    verifier = oauth_data.get("verifier")

    if not verifier:
        return {
            "success": False,
            "step": "pkce",
            "error": "missing_verifier",
            "message": "Code PKCE introuvable."
        }, 400

    token_response = requests.post(
        TOKEN_URL,
        data={
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=30,
    )

    if token_response.status_code != 200:
        return {
            "success": False,
            "step": "token_exchange",
            "status_code": token_response.status_code,
            "error": token_response.text,
        }, 400

    token = token_response.json()

    access_token = token.get("access_token")
    refresh_token = token.get("refresh_token")

    if not access_token:
        return {
            "success": False,
            "step": "access_token",
            "error": "Access token absent."
        }, 400

    oauth_data.clear()

    return {
        "success": True,
        "message": "Autorisation X réussie.",
        "token_saved": True,
        "refresh_token_received": bool(refresh_token),
    }


@app.route("/publish", methods=["POST"])
def publish():
    global access_token

    data = request.get_json(silent=True) or {}
    text = data.get("text")

    if not text:
        return {
            "success": False,
            "step": "publish",
            "error": "missing_text",
            "message": "Le texte de publication est obligatoire."
        }, 400

    if not access_token:
        return {
            "success": False,
            "step": "authentication",
            "error": "no_access_token",
            "message": "Aucun access token. Autorisation nécessaire via /login."
        }, 401

    response = requests.post(
        POST_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json={
            "text": text
        },
        timeout=30,
    )

    return {
        "success": response.status_code in (200, 201),
        "step": "create_post",
        "status_code": response.status_code,
        "x_response": response.text,
    }, response.status_code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
