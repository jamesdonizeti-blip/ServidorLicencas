from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os
from datetime import datetime, timedelta

app = Flask(__name__)

DB_NAME = "licenses.db"
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")  # set in Render environment

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE,
            machine_id TEXT,
            valid_until TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route("/health")
def health():
    return "OK", 200

@app.route("/generate", methods=["POST"])
def generate():
    token = request.headers.get("Authorization")
    if token != ADMIN_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    machine = data.get("machine")
    days = data.get("days", 30)

    if not machine:
        return jsonify({"error": "Missing machine ID"}), 400

    raw = machine + str(datetime.utcnow().timestamp())
    license_key = hashlib.sha256(raw.encode()).hexdigest()
    valid_until = datetime.utcnow() + timedelta(days=days)

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO licenses (license_key, machine_id, valid_until, created_at) VALUES (?, ?, ?, ?)",
        (license_key, machine, valid_until.isoformat(), datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    return jsonify({
        "license": license_key,
        "machine": machine,
        "valid_until": valid_until.isoformat()
    })

@app.route("/check", methods=["GET"])
def check():
    license_key = request.args.get("license")
    machine = request.args.get("machine")

    if not license_key or not machine:
        return jsonify({"valid": False, "reason": "Missing parameters"}), 400

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT machine_id, valid_until FROM licenses WHERE license_key = ?", (license_key,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"valid": False, "reason": "License not found"}), 404

    db_machine, valid_until = row

    if db_machine != machine:
        return jsonify({"valid": False, "reason": "Machine mismatch"}), 403

    if datetime.fromisoformat(valid_until) < datetime.utcnow():
        return jsonify({"valid": False, "reason": "Expired"}), 403

    return jsonify({"valid": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
