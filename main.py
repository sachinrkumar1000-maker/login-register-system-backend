from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data", "user")
os.makedirs(DATA_DIR, exist_ok=True)


def user_folder(email):
    safe_email = email.strip().lower()
    return os.path.join(DATA_DIR, safe_email)


def user_file(email):
    return os.path.join(user_folder(email), "user.json")


@app.route("/")
def home():
    return "Backend is running"


@app.route("/api/check-email")
def check_email():
    email = request.args.get("email", "").strip().lower()
    if not email:
        return jsonify({"exists": False})

    exists = os.path.isfile(user_file(email))
    return jsonify({"exists": exists})


@app.route("/api/signup", methods=["POST"])
def signup():
    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password required"}), 400

    if os.path.isfile(user_file(email)):
        return jsonify({"success": False, "message": "User already exists"}), 409

    os.makedirs(user_folder(email), exist_ok=True)

    with open(user_file(email), "w") as f:
        json.dump({"email": email, "password": password}, f)

    return jsonify({"success": True})


@app.route("/api/debug/users")
def debug_users():
    if not os.path.isdir(DATA_DIR):
        return jsonify([])

    users = []
    for folder_name in os.listdir(DATA_DIR):
        file_path = os.path.join(DATA_DIR, folder_name, "user.json")
        if os.path.isfile(file_path):
            with open(file_path, "r") as f:
                users.append(json.load(f))

    return jsonify(users)


if __name__ == "__main__":
    app.run(debug=True)
