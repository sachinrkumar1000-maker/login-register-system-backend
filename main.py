from flask import Flask, request, jsonify, session
from functools import wraps
import os
import re
import json
import hashlib
import hmac
import time
import threading
import shutil
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


# =====================================================================
# ADMIN
# admin.json lives next to app.py ON THE SERVER ONLY (never on Netlify):
#   {"id": "admin", "password": "your-password"}
# "password" can also be a werkzeug hash (starts with "scrypt:" or "pbkdf2:").
# =====================================================================
ADMIN_FILE = os.path.join(BASE_DIR, "admin.json")
ADMIN_MAX_FAILS = 5
ADMIN_LOCK_SECONDS = 300
_admin_fails = {}  # ip -> (fail_count, first_fail_time)


def client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() if fwd else request.remote_addr) or "unknown"


def load_admin():
    try:
        with open(ADMIN_FILE, "r") as f:
            data = json.load(f)
        return str(data.get("id", "")), str(data.get("password", ""))
    except (OSError, ValueError):
        return "", ""


def admin_password_ok(stored, given):
    if stored.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored, given)
    return hmac.compare_digest(stored.encode(), given.encode())


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return jsonify({"message": "Admin login required"}), 401
        return f(*args, **kwargs)
    return wrapper


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    ip = client_ip()
    count, first = _admin_fails.get(ip, (0, 0))
    if count and time.time() - first > ADMIN_LOCK_SECONDS:
        count, first = 0, 0
    if count >= ADMIN_MAX_FAILS:
        return jsonify({"success": False, "message": "Too many attempts. Try again in a few minutes."}), 429

    body = request.get_json(force=True, silent=True) or {}
    admin_id = str(body.get("id", ""))
    password = str(body.get("password", ""))

    real_id, real_pass = load_admin()
    id_ok = bool(real_id) and hmac.compare_digest(real_id.encode(), admin_id.encode())
    pass_ok = bool(real_pass) and admin_password_ok(real_pass, password)

    if not (id_ok and pass_ok):
        _admin_fails[ip] = (count + 1, first or time.time())
        return jsonify({"success": False, "message": "Invalid admin ID or password"}), 401

    _admin_fails.pop(ip, None)
    session.permanent = True
    session["admin"] = True
    return jsonify({"success": True})


@app.route("/api/admin/me")
def admin_me():
    if not session.get("admin"):
        return no_store(jsonify({"admin": False})), 401
    return no_store(jsonify({"admin": True}))


@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin", None)
    return jsonify({"success": True})


# ---------- Customers (stored in customers.json next to app.py) ----------
CUSTOMERS_FILE = os.path.join(BASE_DIR, "customers.json")
_customers_lock = threading.Lock()
CUSTOMER_STATUSES = ("active", "paused")


def read_customers():
    try:
        with open(CUSTOMERS_FILE, "r") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def write_customers(customers):
    tmp = CUSTOMERS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(customers, f, indent=2)
    os.replace(tmp, CUSTOMERS_FILE)


def find_customer(customers, email):
    for c in customers:
        if c.get("email") == email:
            return c
    return None


@app.route("/api/admin/customers")
@admin_required
def admin_customers():
    customers = sorted(read_customers(), key=lambda c: c.get("added", 0), reverse=True)
    return no_store(jsonify({"customers": customers, "count": len(customers)}))


@app.route("/api/admin/customers/add", methods=["POST"])
@admin_required
def admin_add_customer():
    body = request.get_json(force=True, silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    if not valid_email(email):
        return jsonify({"success": False, "message": "Enter a valid email address"}), 400

    with _customers_lock:
        customers = read_customers()
        if find_customer(customers, email):
            return jsonify({"success": False, "message": "Customer already exists"}), 409
        customers.append({
            "email": email,
            "added": int(time.time()),
            "status": "active",
            "notes": "",
        })
        write_customers(customers)
    return jsonify({"success": True})


@app.route("/api/admin/customers/detail")
@admin_required
def admin_customer_detail():
    email = request.args.get("email", "").strip().lower()
    customer = find_customer(read_customers(), email)
    if not customer:
        return jsonify({"message": "Customer not found"}), 404
    return no_store(jsonify({"customer": customer}))


@app.route("/api/admin/customers/update", methods=["POST"])
@admin_required
def admin_update_customer():
    body = request.get_json(force=True, silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    status = str(body.get("status", "active"))
    notes = str(body.get("notes", ""))[:5000]
    if status not in CUSTOMER_STATUSES:
        return jsonify({"success": False, "message": "Invalid status"}), 400

    with _customers_lock:
        customers = read_customers()
        customer = find_customer(customers, email)
        if not customer:
            return jsonify({"success": False, "message": "Customer not found"}), 404
        customer["status"] = status
        customer["notes"] = notes
        write_customers(customers)
    return jsonify({"success": True})


@app.route("/api/admin/customers/delete", methods=["POST"])
@admin_required
def admin_delete_customer():
    body = request.get_json(force=True, silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    with _customers_lock:
        customers = read_customers()
        remaining = [c for c in customers if c.get("email") != email]
        if len(remaining) == len(customers):
            return jsonify({"success": False, "message": "Customer not found"}), 404
        write_customers(remaining)
    return jsonify({"success": True})


if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
