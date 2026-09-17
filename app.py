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

    auth_url = AUTH_URL + "?" + urlencode(params)

    return redirect(auth_url)


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

    token_data = {
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    }

    response = requests.post(
        TOKEN_URL,
        data=token_data,
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
        "token_type": token.get("token_type"),
        "scope": token.get("scope"),
        "has_refresh_token": bool(token.get("refresh_token"))
    }


@app.route("/test-post")
def test_post():
    refresh_token = os.environ.get("X_REFRESH_TOKEN")

    if not refresh_token:
        return {
            "posted": False,
            "error": "X_REFRESH_TOKEN absent"
        }, 500

    # 1. Utiliser le refresh token UNE SEULE FOIS
    token_response = requests.post(
        TOKEN_URL,
        data={
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=30
    )

    if token_response.status_code != 200:
        return {
            "posted": False,
            "step": "refresh_token",
            "status_code": token_response.status_code,
            "error": token_response.text
        }, 400

    token = token_response.json()

    access_token = token.get("access_token")
    new_refresh_token = token.get("refresh_token")

    if not access_token:
        return {
            "posted": False,
            "step": "access_token",
            "error": "Access token absent"
        }, 400

    # 2. Utiliser immédiatement le nouvel access token
    post_response = requests.post(
        POST_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        },
        json={
            "text": "⚽ Goal Sphere est maintenant connecté à X. Premier test d'automatisation réussi. 🚀"
        },
        timeout=30
    )

    if post_response.status_code not in [200, 201]:
        return {
            "posted": False,
            "step": "create_post",
            "status_code": post_response.status_code,
            "error": post_response.text
        }, 400

    result = {
        "posted": True,
        "message": "Post publié avec succès sur X.",
        "post_response": post_response.json()
    }

    # Indique si X a fourni un nouveau refresh token
    if new_refresh_token:
        result["new_refresh_token_received"] = True
    else:
        result["new_refresh_token_received"] = False

    return result


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)    oauth_data.clear()

    return {
    "message": "Authentification X réussie",
    "token_received": True,
    "token_type": token.get("token_type"),
    "scope": token.get("scope"),
    "has_refresh_token": bool(token.get("refresh_token")),
    "refresh_token": token.get("refresh_token")
    }

@app.route("/test-auth")
def test_auth():
    refresh_token = os.environ.get("X_REFRESH_TOKEN")

    if not refresh_token:
        return {
            "authenticated": False,
            "error": "X_REFRESH_TOKEN absent"
        }, 500

    data = {
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID
    }

    response = requests.post(
        TOKEN_URL,
        data=data,
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=30
    )

    if response.status_code != 200:
        return {
            "authenticated": False,
            "status_code": response.status_code,
            "error": response.text
        }, 400

    token = response.json()

    return {
        "authenticated": True,
        "token_type": token.get("token_type"),
        "scope": token.get("scope"),
        "has_access_token": bool(token.get("access_token")),
        "has_refresh_token": bool(token.get("refresh_token"))
    }

@app.route("/test-post")
def test_post():
    refresh_token = os.environ.get("X_REFRESH_TOKEN")

    if not refresh_token:
        return {
            "posted": False,
            "error": "X_REFRESH_TOKEN absent"
        }, 500

    # Obtenir un nouvel access token
    token_data = {
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID
    }

    token_response = requests.post(
        TOKEN_URL,
        data=token_data,
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=30
    )

    if token_response.status_code != 200:
        return {
            "posted": False,
            "step": "refresh_token",
            "status_code": token_response.status_code,
            "error": token_response.text
        }, 400

    token = token_response.json()
    access_token = token.get("access_token")
    new_refresh_token = token.get("refresh_token")

    if not access_token:
        return {
            "posted": False,
            "step": "access_token",
            "error": "Access token absent"
        }, 400

    # Publier sur X
    post_response = requests.post(
        "https://api.x.com/2/tweets",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        },
        json={
            "text": "⚽ Goal Sphere est maintenant connecté à X. Premier test d'automatisation réussi. 🚀"
        },
        timeout=30
    )

    if post_response.status_code not in [200, 201]:
        return {
            "posted": False,
            "step": "create_post",
            "status_code": post_response.status_code,
            "error": post_response.text
        }, 400

    result = {
        "posted": True,
        "message": "Post publié avec succès sur X.",
        "response": post_response.json()
    }

    # Indique seulement qu'un nouveau refresh token existe.
    # Ne l'affiche pas dans le navigateur.
    if new_refresh_token:
        result["new_refresh_token_received"] = True
        result["action"] = "Mettre à jour X_REFRESH_TOKEN dans Render avec le nouveau refresh token."

    return result

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
