import os
import base64
import hashlib
import secrets
from urllib.parse import urlencode

import requests
import psycopg
import tweepy
from flask import Flask, request, redirect

app = Flask(__name__)

CLIENT_ID = os.environ.get("X_CLIENT_ID")
CLIENT_SECRET = os.environ.get("X_CLIENT_SECRET")

X_CONSUMER_KEY = os.environ.get("X_CONSUMER_KEY")
X_CONSUMER_SECRET = os.environ.get("X_CONSUMER_SECRET")
X_ACCESS_TOKEN = os.environ.get("X_ACCESS_TOKEN")
X_ACCESS_TOKEN_SECRET = os.environ.get("X_ACCESS_TOKEN_SECRET")

DATABASE_URL = os.environ.get("DATABASE_URL")

REDIRECT_URI = "https://goalsphere-x-callback.onrender.com/callback"

AUTH_URL = "https://twitter.com/i/oauth2/authorize"
TOKEN_URL = "https://api.x.com/2/oauth2/token"
POST_URL = "https://api.x.com/2/tweets"

SCOPES = "tweet.read tweet.write users.read offline.access"

oauth_data = {}


# ============================================================
# DATABASE
# ============================================================

def init_database():
    if not DATABASE_URL:
        print("ERREUR : DATABASE_URL absente.")
        return

    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS x_tokens (
                        id INTEGER PRIMARY KEY,
                        access_token TEXT,
                        refresh_token TEXT
                    )
                """)
            conn.commit()

        print("Base PostgreSQL initialisée.")

    except Exception as e:
        print(f"ERREUR PostgreSQL : {e}")


def save_tokens(access_token, refresh_token=None):
    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:

                cur.execute("""
                    INSERT INTO x_tokens (id, access_token, refresh_token)
                    VALUES (1, %s, %s)
                    ON CONFLICT (id)
                    DO UPDATE SET
                        access_token = EXCLUDED.access_token,
                        refresh_token = COALESCE(
                            EXCLUDED.refresh_token,
                            x_tokens.refresh_token
                        )
                """, (access_token, refresh_token))

            conn.commit()

        print("Tokens sauvegardés dans PostgreSQL.")
        return True

    except Exception as e:
        print(f"ERREUR sauvegarde tokens : {e}")
        return False


def load_tokens():
    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:

                cur.execute("""
                    SELECT access_token, refresh_token
                    FROM x_tokens
                    WHERE id = 1
                """)

                row = cur.fetchone()

        if row:
            print("Tokens récupérés depuis PostgreSQL.")
            return row[0], row[1]

        print("Aucun token trouvé dans PostgreSQL.")
        return None, None

    except Exception as e:
        print(f"ERREUR lecture PostgreSQL : {e}")
        return None, None


# ============================================================
# PKCE
# ============================================================

def create_pkce():
    verifier = secrets.token_urlsafe(64)

    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()

    return verifier, challenge


# ============================================================
# REFRESH TOKEN
# ============================================================

def refresh_access_token():
    access_token, refresh_token = load_tokens()

    if not refresh_token:
        print("Aucun refresh token disponible.")
        return None

    print("Tentative de renouvellement du token X...")

    response = requests.post(
        TOKEN_URL,
        data={
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=30,
    )

    print(f"Refresh HTTP Status : {response.status_code}")
    print(f"Refresh réponse X : {response.text}")

    if response.status_code != 200:
        return None

    token = response.json()

    new_access_token = token.get("access_token")
    new_refresh_token = token.get("refresh_token")

    if not new_access_token:
        return None

    save_tokens(
        new_access_token,
        new_refresh_token
    )

    return new_access_token


# ============================================================
# ROUTES
# ============================================================

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

    saved = save_tokens(
        access_token,
        refresh_token
    )

    if not saved:
        return {
            "success": False,
            "step": "database",
            "error": "Impossible de sauvegarder les tokens."
        }, 500

    oauth_data.clear()

    return {
        "success": True,
        "message": "Autorisation X réussie.",
        "token_saved": True,
        "refresh_token_received": bool(refresh_token),
        "storage": "PostgreSQL",
    }


# ============================================================
# PUBLICATION PHOTO X
# ============================================================

@app.route("/publish-photo", methods=["POST"])
def publish_photo():
    try:

        # ====================================================
        # 1. Vérifier l'image
        # ====================================================

        if "image" not in request.files:
            return {
                "success": False,
                "step": "upload",
                "error": "Aucune image reçue."
            }, 400

        image = request.files["image"]

        if not image.filename:
            return {
                "success": False,
                "step": "upload",
                "error": "Nom de fichier absent."
            }, 400

        text = request.form.get("text", "")

        print("========================================")
        print("Début publication avec photo")
        print(f"Image : {image.filename}")

        # ====================================================
        # 2. Vérifier OAuth 1.0a
        # ====================================================

        if not all([
            X_CONSUMER_KEY,
            X_CONSUMER_SECRET,
            X_ACCESS_TOKEN,
            X_ACCESS_TOKEN_SECRET
        ]):
            return {
                "success": False,
                "step": "authentication",
                "error": "oauth1_credentials_missing"
            }, 500

        # ====================================================
        # 3. Créer le client OAuth 1.0a
        # ====================================================

        auth = tweepy.OAuth1UserHandler(
            X_CONSUMER_KEY,
            X_CONSUMER_SECRET,
            X_ACCESS_TOKEN,
            X_ACCESS_TOKEN_SECRET
        )

        api = tweepy.API(auth)

        # ====================================================
        # 4. Sauvegarder temporairement l'image
        # ====================================================

        import tempfile

        temp_file = tempfile.NamedTemporaryFile(
            delete=False,
            suffix=os.path.splitext(image.filename)[1]
        )

        temp_path = temp_file.name

        try:
            image.save(temp_path)
            temp_file.close()

            print(f"Image temporaire : {temp_path}")
            print("Upload de l'image vers X...")

            # ====================================================
            # 5. Upload de l'image avec OAuth 1.0a
            # ====================================================


            print("=== DEBUG OAUTH1 ===")
            print("Consumer Key présent :", bool(X_CONSUMER_KEY))
            print("Consumer Secret présent :", bool(X_CONSUMER_SECRET))
            print("Access Token présent :", bool(X_ACCESS_TOKEN))
            print("Access Token Secret présent :", bool(X_ACCESS_TOKEN_SECRET))
            print("Longueur Consumer Key :", len(X_CONSUMER_KEY or ""))
            print("Longueur Access Token :", len(X_ACCESS_TOKEN or ""))
            media = api.media_upload(
                filename=temp_path
            )

            media_id = media.media_id

            print("Image uploadée avec succès.")
            print(f"Media ID : {media_id}")

            # ====================================================
            # 6. Créer le client X avec OAuth 1.0a
            # ====================================================

            client = tweepy.Client(
                consumer_key=X_CONSUMER_KEY,
                consumer_secret=X_CONSUMER_SECRET,
                access_token=X_ACCESS_TOKEN,
                access_token_secret=X_ACCESS_TOKEN_SECRET
            )

            # ====================================================
            # 7. Publier le post avec la photo
            # ====================================================

            response = client.create_tweet(
                text=text,
                media_ids=[media_id]
            )

            print("POST PHOTO RÉUSSI")
            print(f"X RESPONSE : {response}")
            print("========================================")

            return {
                "success": True,
                "step": "create_post",
                "media_id": str(media_id),
                "status_code": 201,
                "x_response": str(response)
            }, 201

        finally:
            # Suppression du fichier temporaire
            try:
                os.remove(temp_path)
                print("Image temporaire supprimée.")
            except Exception:
                pass

    except tweepy.TweepyException as e:

        print(f"ERREUR TWEEPY : {e}")

        return {
            "success": False,
            "step": "media_upload",
            "error": str(e)
        }, 500

    except Exception as e:

        print(f"ERREUR PHOTO : {e}")

        return {
            "success": False,
            "step": "exception",
            "error": str(e)
        }, 500

@app.route("/test-database")
def test_database():

    access_token, refresh_token = load_tokens()

    return {
        "database": "connected",
        "access_token_present": bool(access_token),
        "refresh_token_present": bool(refresh_token)
    }
        
# ============================================================
# PUBLICATION TEXTE X
# ============================================================

@app.route("/publish", methods=["POST"])
def publish():

    data = request.get_json(silent=True) or {}
    text = data.get("text")

    if not text:
        return {
            "success": False,
            "step": "publish",
            "error": "missing_text",
            "message": "Le texte de publication est obligatoire."
        }, 400

    # Récupération depuis PostgreSQL
    access_token, refresh_token = load_tokens()

    if not access_token:
        return {
            "success": False,
            "step": "authentication",
            "error": "no_access_token",
            "message": "Aucun access token. Autorisation nécessaire via /login."
        }, 401

    # Première tentative
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

    print(f"Publication HTTP Status : {response.status_code}")
    print(f"Réponse X : {response.text}")

    # Si le token est refusé, tentative de renouvellement
    if response.status_code in (401, 403):

        print("Token probablement invalide. Tentative de refresh...")

        new_access_token = refresh_access_token()

        if new_access_token:

            response = requests.post(
                POST_URL,
                headers={
                    "Authorization": f"Bearer {new_access_token}",
                    "Content-Type": "application/json",
                },
                json={
                    "text": text
                },
                timeout=30,
            )

            print(
                f"Nouvelle tentative HTTP Status : "
                f"{response.status_code}"
            )

            print(
                f"Nouvelle réponse X : "
                f"{response.text}"
            )

    return {
        "success": response.status_code in (200, 201),
        "step": "create_post",
        "status_code": response.status_code,
        "x_response": response.text,
    }, response.status_code


# ============================================================
# STARTUP
# ============================================================

init_database()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000
)
