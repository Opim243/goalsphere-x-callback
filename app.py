from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    return "Goal Sphere X Callback is running."

@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")

    return {
        "message": "OAuth callback received",
        "code_received": bool(code),
        "state_received": bool(state)
    }

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
