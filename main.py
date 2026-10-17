from flask import Flask, request, jsonify, session
from functools import wraps
import os
import re
import json
import hashlib
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data", "user")
os.makedirs(DATA_DIR, exist_ok=True)


# ---------- Secret key (persists across restarts so sessions stay valid) ----------
def load_secret_key():
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    key_path = os.path.join(BASE_DIR, "secret.key")
    if not os.path.isfile(key_path):
        with open(key_path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(key_path) as f:
        return f.read().strip()


app.secret_key = load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,  # browser talks to Netlify over HTTPS
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7,  # 7 days
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_email(email):
    return bool(email) and len(email) <= 254 and EMAIL_RE.match(email)


def user_folder(email):
    # Hash the email so it can never be used for path traversal
    folder = hashlib.sha256(email.encode()).hexdigest()
    return os.path.join(DATA_DIR, folder)


def user_file(email):
    return os.path.join(user_folder(email), "user.json")


def no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "email" not in session:
            return jsonify({"message": "Not logged in"}), 401
        return f(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    return "Backend is running"


@app.route("/api/check-email")
def check_email():
    email = request.args.get("email", "").strip().lower()
    if not valid_email(email):
        return jsonify({"exists": False})
    return jsonify({"exists": os.path.isfile(user_file(email))})


@app.route("/api/signup", methods=["POST"])
def signup():
    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password required"}), 400

    if not valid_email(email):
        return jsonify({"success": False, "message": "Invalid email address"}), 400

    if len(password) < 8:
        return jsonify({"success": False, "message": "Password must be at least 8 characters"}), 400

    if os.path.isfile(user_file(email)):
        return jsonify({"success": False, "message": "User already exists"}), 409

    os.makedirs(user_folder(email), exist_ok=True)
    with open(user_file(email), "w") as f:
        json.dump({"email": email, "password_hash": generate_password_hash(password)}, f)

    return jsonify({"success": True})


@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")

    if not email or not password:
        return jsonify({"success": False, "field": "general", "message": "Email and password required"}), 400

    if not valid_email(email) or not os.path.isfile(user_file(email)):
        return jsonify({"success": False, "field": "email", "message": "No user found with this email"}), 404

    with open(user_file(email), "r") as f:
        user = json.load(f)

    if not check_password_hash(user.get("password_hash", ""), password):
        return jsonify({"success": False, "field": "password", "message": "Incorrect password"}), 401

    session.clear()
    session.permanent = True
    session["email"] = email
    return jsonify({"success": True})


@app.route("/api/me")
def me():
    email = session.get("email")
    if not email:
        return no_store(jsonify({"loggedIn": False})), 401
    return no_store(jsonify({"loggedIn": True, "email": email}))


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})


if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
