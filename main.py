from flask import Flask, request, jsonify, session
from functools import wraps
import os
import re
import json
import hashlib
import hmac
import math
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


def is_customer(email):
    # True only if this email is listed in customers.json (see Customers section below)
    return any(c.get("email") == email for c in read_customers())


def customer_required(f):
    # Use under @login_required on any route only customers may use
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_customer(session.get("email", "")):
            return jsonify({"message": "No active campaigns"}), 403
        return f(*args, **kwargs)
    return wrapper


@app.route("/api/me")
def me():
    email = session.get("email")
    if not email:
        return no_store(jsonify({"loggedIn": False})), 401
    return no_store(jsonify({
        "loggedIn": True,
        "email": email,
        "isCustomer": is_customer(email),
    }))


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
            "campaigns": [],
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


# ---------- Campaigns (stored inside each customer in customers.json) ----------
MIN_VIEWS, MAX_VIEWS = 1000, 99999999
MIN_DAYS, MAX_DAYS = 1, 365
MAX_CPM = 1000000


def to_int(value):
    """Whole number or None. Rejects booleans, fractions, NaN/inf, junk."""
    if isinstance(value, bool):
        return None
    try:
        f = float(value)
        if f != int(f):
            return None
        return int(f)
    except (TypeError, ValueError, OverflowError):
        return None


def to_cpm(value):
    """Non-negative number (max 2 decimals kept) or None."""
    if isinstance(value, bool):
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(f) or f < 0 or f > MAX_CPM:
        return None
    return round(f, 2)


def find_campaign(customer, campaign_id):
    for camp in customer.get("campaigns", []):
        if camp.get("id") == campaign_id:
            return camp
    return None


@app.route("/api/admin/campaigns/add", methods=["POST"])
@admin_required
def admin_add_campaign():
    body = request.get_json(force=True, silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    name = str(body.get("name", "")).strip()[:80]
    total_views = to_int(body.get("total_views"))
    duration = to_int(body.get("duration_days"))

    if not name:
        return jsonify({"success": False, "message": "Campaign name is required"}), 400
    if total_views is None or not (MIN_VIEWS <= total_views <= MAX_VIEWS):
        return jsonify({"success": False, "message": f"Total views must be between {MIN_VIEWS} and {MAX_VIEWS}"}), 400
    if duration is None or not (MIN_DAYS <= duration <= MAX_DAYS):
        return jsonify({"success": False, "message": f"Duration must be between {MIN_DAYS} and {MAX_DAYS} days"}), 400

    with _customers_lock:
        customers = read_customers()
        customer = find_customer(customers, email)
        if not customer:
            return jsonify({"success": False, "message": "Customer not found"}), 404
        campaign = {
            "id": secrets.token_hex(4),
            "name": name,
            "total_views": total_views,
            "duration_days": duration,
            "views_done": 0,
            "days_done": 0,
            "cpm": 0,
            "created": int(time.time()),
        }
        customer.setdefault("campaigns", []).append(campaign)
        write_customers(customers)
    return jsonify({"success": True, "id": campaign["id"]})


@app.route("/api/admin/campaigns/update", methods=["POST"])
@admin_required
def admin_update_campaign():
    body = request.get_json(force=True, silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    campaign_id = str(body.get("id", ""))
    views_done = to_int(body.get("views_done"))
    days_done = to_int(body.get("days_done"))
    cpm = to_cpm(body.get("cpm"))

    with _customers_lock:
        customers = read_customers()
        customer = find_customer(customers, email)
        camp = find_campaign(customer, campaign_id) if customer else None
        if not camp:
            return jsonify({"success": False, "message": "Campaign not found"}), 404

        if views_done is None or not (0 <= views_done <= camp["total_views"]):
            return jsonify({"success": False, "message": f"Views delivered must be between 0 and {camp['total_views']}"}), 400
        if days_done is None or not (0 <= days_done <= camp["duration_days"]):
            return jsonify({"success": False, "message": f"Days completed must be between 0 and {camp['duration_days']}"}), 400
        if cpm is None:
            return jsonify({"success": False, "message": "CPM must be a number of 0 or more"}), 400

        camp["views_done"] = views_done
        camp["days_done"] = days_done
        camp["cpm"] = cpm
        write_customers(customers)
    return jsonify({"success": True})


@app.route("/api/admin/campaigns/delete", methods=["POST"])
@admin_required
def admin_delete_campaign():
    body = request.get_json(force=True, silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    campaign_id = str(body.get("id", ""))

    with _customers_lock:
        customers = read_customers()
        customer = find_customer(customers, email)
        camps = customer.get("campaigns", []) if customer else []
        remaining = [c for c in camps if c.get("id") != campaign_id]
        if not customer or len(remaining) == len(camps):
            return jsonify({"success": False, "message": "Campaign not found"}), 404
        customer["campaigns"] = remaining
        write_customers(customers)
    return jsonify({"success": True})


# What a logged-in customer sees on the home page
@app.route("/api/campaigns")
@login_required
@customer_required
def my_campaigns():
    customer = find_customer(read_customers(), session.get("email", ""))
    campaigns = customer.get("campaigns", []) if customer else []
    campaigns = sorted(campaigns, key=lambda c: c.get("created", 0), reverse=True)
    return no_store(jsonify({"campaigns": campaigns}))


# ---------- Chat (one file per customer: chats/chat-<email>.json) ----------
CHATS_DIR = os.path.join(BASE_DIR, "chats")
os.makedirs(CHATS_DIR, exist_ok=True)
_chat_lock = threading.Lock()
MAX_CHAT_LEN = 2000
MAX_CHAT_MESSAGES = 2000
FILE_SAFE_EMAIL = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9\-]+(\.[a-z0-9\-]+)*\.[a-z]{2,}$")


def chat_path(email):
    # Normal emails give chat-<email>.json. Anything odd (slashes, "..", very long)
    # falls back to a hash so an email can never escape the chats folder.
    if len(email) <= 200 and FILE_SAFE_EMAIL.match(email) and ".." not in email:
        name = "chat-" + email + ".json"
    else:
        name = "chat-" + hashlib.sha256(email.encode()).hexdigest() + ".json"
    return os.path.join(CHATS_DIR, name)


def read_chat(email):
    chat = {"email": email, "next_id": 1, "customer_read": 0, "admin_read": 0, "messages": []}
    try:
        with open(chat_path(email), "r") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("messages"), list):
            chat.update(data)
            if chat["messages"]:
                chat["next_id"] = max(chat.get("next_id", 1), chat["messages"][-1]["id"] + 1)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return chat


def write_chat(email, chat):
    path = chat_path(email)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(chat, f, indent=2)
    os.replace(tmp, path)


def chat_unread(chat, viewer):
    other = "admin" if viewer == "customer" else "customer"
    last = chat.get(viewer + "_read", 0)
    return sum(1 for m in chat["messages"] if m.get("from") == other and m.get("id", 0) > last)


def chat_fetch(email, viewer):
    after = to_int(request.args.get("after", "0"))
    if after is None or after < 0:
        after = 0
    with _chat_lock:
        chat = read_chat(email)
        msgs = [m for m in chat["messages"] if m["id"] > after]
        if after == 0:
            msgs = msgs[-300:]
        latest = chat["messages"][-1]["id"] if chat["messages"] else 0
        if chat.get(viewer + "_read", 0) < latest:
            chat[viewer + "_read"] = latest  # the viewer has now seen everything
            write_chat(email, chat)
    return no_store(jsonify({"messages": msgs}))


def chat_send(email, sender):
    body = request.get_json(force=True, silent=True) or {}
    text = str(body.get("text", "")).replace("\r\n", "\n").strip()
    if not text:
        return jsonify({"success": False, "message": "Message is empty"}), 400
    if len(text) > MAX_CHAT_LEN:
        return jsonify({"success": False, "message": f"Message is too long (max {MAX_CHAT_LEN} characters)"}), 400

    with _chat_lock:
        chat = read_chat(email)
        msg = {"id": chat["next_id"], "from": sender, "text": text, "time": int(time.time())}
        chat["next_id"] = msg["id"] + 1
        chat["messages"].append(msg)
        chat["messages"] = chat["messages"][-MAX_CHAT_MESSAGES:]
        chat[sender + "_read"] = msg["id"]  # sending counts as having read the thread
        write_chat(email, chat)
    return jsonify({"success": True, "message": msg})


# --- customer side ---
@app.route("/api/chat")
@login_required
@customer_required
def customer_chat():
    return chat_fetch(session["email"], "customer")


@app.route("/api/chat/unread")
@login_required
@customer_required
def customer_chat_unread():
    chat = read_chat(session["email"])
    return no_store(jsonify({"unread": chat_unread(chat, "customer")}))


@app.route("/api/chat/send", methods=["POST"])
@login_required
@customer_required
def customer_chat_send():
    return chat_send(session["email"], "customer")


# --- admin side ---
def admin_chat_email():
    email = request.args.get("email", "").strip().lower()
    if not email and request.is_json:
        email = str((request.get_json(silent=True) or {}).get("email", "")).strip().lower()
    return email if find_customer(read_customers(), email) else None


@app.route("/api/admin/chat")
@admin_required
def admin_chat():
    email = admin_chat_email()
    if not email:
        return jsonify({"message": "Customer not found"}), 404
    return chat_fetch(email, "admin")


@app.route("/api/admin/chat/send", methods=["POST"])
@admin_required
def admin_chat_send():
    email = admin_chat_email()
    if not email:
        return jsonify({"success": False, "message": "Customer not found"}), 404
    return chat_send(email, "admin")


@app.route("/api/admin/chat/unread")
@admin_required
def admin_chat_unread():
    unread = {}
    for c in read_customers():
        email = c.get("email", "")
        n = chat_unread(read_chat(email), "admin")
        if n:
            unread[email] = n
    return no_store(jsonify({"unread": unread, "total": sum(unread.values())}))


if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
