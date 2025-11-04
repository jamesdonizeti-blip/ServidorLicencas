# app.py
from flask import Flask, request, jsonify, render_template, redirect, url_for
import sqlite3, hashlib, os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__, template_folder="templates")

DB = "licenses.db"
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "JAMES2025-SUPERSEG")

# ------------------------------
# DB helpers
# ------------------------------
def get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT UNIQUE,
        hwid TEXT,
        valid_until TEXT,
        created_at TEXT,
        revoked INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS activations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT,
        hwid TEXT,
        ip TEXT,
        ts TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ------------------------------
# Decorator admin
# ------------------------------
def require_admin_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = (
            request.headers.get("Authorization")
            or request.headers.get("X-Admin-Token")
            or request.args.get("token")
        )
        if token != ADMIN_TOKEN:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

# ------------------------------
# Health
# ------------------------------
@app.route("/health")
def health():
    return "OK", 200

# ------------------------------
# Generate license (API)
# ------------------------------
@app.route("/generate", methods=["POST"])
@require_admin_token
def generate():
    data = request.get_json(force=True)
    hwid = data.get("hwid")
    days = int(data.get("days", 30))

    if not hwid:
        return jsonify({"error": "hwid required"}), 400

    raw = hwid + str(datetime.utcnow().timestamp())
    license_key = hashlib.sha256(raw.encode()).hexdigest()

    valid_until = (datetime.utcnow() + timedelta(days=days)).isoformat()

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO licenses (license_key, hwid, valid_until, created_at) VALUES (?, ?, ?, ?)",
        (license_key, hwid, valid_until, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()

    return jsonify({"license": license_key, "hwid": hwid, "valid_until": valid_until})

# ------------------------------
# Check license (client)
# ------------------------------
@app.route("/check", methods=["GET"])
def check():
    license_key = request.args.get("license")
    hwid = request.args.get("hwid")

    if not license_key or not hwid:
        return jsonify({"valid": False, "reason": "missing parameters"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT hwid, valid_until, revoked FROM licenses WHERE license_key = ?",
        (license_key,),
    )
    row = cur.fetchone()

    if not row:
        return jsonify({"valid": False, "reason": "not found"}), 404

    if row["revoked"] == 1:
        return jsonify({"valid": False, "reason": "revoked"}), 403

    if row["hwid"] != hwid:
        return jsonify({"valid": False, "reason": "hwid mismatch"}), 403

    if datetime.fromisoformat(row["valid_until"]) < datetime.utcnow():
        return jsonify({"valid": False, "reason": "expired"}), 403

    cur.execute(
        "INSERT INTO activations (license_key, hwid, ip, ts) VALUES (?, ?, ?, ?)",
        (license_key, hwid, request.remote_addr, datetime.utcnow().isoformat()),
    )

    conn.commit()
    conn.close()

    return jsonify({"valid": True})

# =========================================================
# ✅ NOVO PAINEL ADMIN MODERNO (Bootstrap + estatísticas)
# =========================================================
def dict_rows(rows):
    return [dict(r) for r in rows]

@app.route("/admin", methods=["GET"])
def admin_index():
    token = (
        request.args.get("token")
        or request.headers.get("Authorization")
        or request.headers.get("X-Admin-Token")
    )
    if token != ADMIN_TOKEN:
        return "Unauthorized", 401

    conn = get_conn()
    cur = conn.cursor()

    # stats
    now = datetime.utcnow().isoformat()

    cur.execute("SELECT COUNT(*) FROM licenses")
    total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM licenses WHERE revoked = 1")
    revoked = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(*) FROM licenses WHERE revoked = 0 AND valid_until > ?",
        (now,),
    )
    valid = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM activations")
    activ = cur.fetchone()[0]

    # list
    cur.execute("SELECT * FROM licenses ORDER BY id DESC LIMIT 200")
    licenses = dict_rows(cur.fetchall())

    cur.execute("SELECT * FROM activations ORDER BY id DESC LIMIT 20")
    activations = dict_rows(cur.fetchall())

    conn.close()

    stats = {
        "total": total,
        "valid": valid,
        "revoked": revoked,
        "activations": activ,
    }

    return render_template(
        "admin.html",
        token=token,
        stats=stats,
        licenses=licenses,
        activations=activations,
    )

# ------------------------------
# Admin create
# ------------------------------
@app.route("/admin/create", methods=["POST"])
def admin_create():
    token = request.args.get("token")
    if token != ADMIN_TOKEN:
        return "Unauthorized", 401

    hwid = request.form.get("hwid")
    days = int(request.form.get("days", 30))

    raw = hwid + str(datetime.utcnow().timestamp())
    license_key = hashlib.sha256(raw.encode()).hexdigest()

    valid_until = (datetime.utcnow() + timedelta(days=days)).isoformat()

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO licenses (license_key, hwid, valid_until, created_at) VALUES (?, ?, ?, ?)",
        (license_key, hwid, valid_until, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()

    return redirect(url_for("admin_index", token=token))

# ------------------------------
# Admin revoke
# ------------------------------
@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    token = request.args.get("token")
    if token != ADMIN_TOKEN:
        return "Unauthorized", 401

    license_key = request.form.get("license_key")

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE licenses SET revoked = 1 WHERE license_key = ?", (license_key,))
    conn.commit()
    conn.close()

    return redirect(url_for("admin_index", token=token))

# ------------------------------
# List activations JSON
# ------------------------------
@app.route("/admin/activations")
@require_admin_token
def admin_activations():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT * FROM activations ORDER BY id DESC LIMIT 200")
    rows = dict_rows(cur.fetchall())

    conn.close()
    return jsonify(rows)

# ------------------------------
# run server
# ------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
