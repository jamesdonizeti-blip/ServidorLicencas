import os, json, base64, sqlite3, datetime
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)

DB_FILE = "licenses.db"
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
PRIVATE_KEY_PATH = "private.pem"

def db():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    conn = db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS LICENSES (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT UNIQUE,
        max_ativacoes INTEGER,
        ativacoes_usadas INTEGER DEFAULT 0,
        ativo INTEGER DEFAULT 1
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS ACTIVATIONS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT,
        hwid TEXT,
        data TEXT,
        ip TEXT
    )
    """)
    conn.commit()
    conn.close()

def get_private_key():
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise RuntimeError("private.pem não encontrado. Gere as chaves primeiro.")
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def assinar(payload: str) -> str:
    private_key = get_private_key()
    assinatura = private_key.sign(
        payload.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(assinatura).decode("utf-8")

@app.route("/activate", methods=["POST"])
def activate():
    dados = request.get_json(force=True)
    license_key = dados.get("license_key", "").strip()
    hwid = dados.get("hwid", "").strip()

    conn = db()
    c = conn.cursor()
    c.execute("SELECT max_ativacoes, ativacoes_usadas, ativo FROM LICENSES WHERE license_key = ?", (license_key,))
    row = c.fetchone()

    if not row:
        return jsonify({"erro": "Licença inexistente"}), 404

    max_ativ, used, ativo = row

    if ativo == 0:
        return jsonify({"erro": "Licença revogada"}), 403

    if used >= max_ativ:
        return jsonify({"erro": "Limite de ativações excedido"}), 403

    c.execute(
        "INSERT INTO ACTIVATIONS (license_key, hwid, data, ip) VALUES (?, ?, ?, ?)",
        (license_key, hwid, datetime.datetime.utcnow().isoformat() + "Z", request.remote_addr)
    )
    c.execute("UPDATE LICENSES SET ativacoes_usadas = ativacoes_usadas + 1 WHERE license_key = ?", (license_key,))
    conn.commit()
    conn.close()

    payload = {
        "license_key": license_key,
        "hwid": hwid,
        "issued": datetime.datetime.utcnow().isoformat() + "Z"
    }
    signature = assinar(json.dumps(payload, separators=(',',':')))
    return jsonify({"payload": payload, "signature": signature})

@app.route("/verify", methods=["POST"])
def verify():
    dados = request.get_json(force=True)
    lic = dados.get("license_key", "").strip()

    conn = db()
    c = conn.cursor()
    c.execute("SELECT ativo FROM LICENSES WHERE license_key = ?", (lic,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"valid": False})

    return jsonify({"valid": row[0] == 1})

@app.route("/admin/add_license", methods=["POST"])
def admin_add_license():
    token = request.headers.get("X-Admin-Token", "")
    if token != ADMIN_TOKEN:
        return jsonify({"erro": "não autorizado"}), 401

    dados = request.get_json(force=True)
    license_key = dados.get("license_key", "").strip()
    max_ativacoes = int(dados.get("max_ativacoes", 1))

    conn = db()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO LICENSES (license_key, max_ativacoes) VALUES (?, ?)",
            (license_key, max_ativacoes)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"erro": "license_key já existe"}), 409

    conn.close()
    return jsonify({"ok": True, "license_key": license_key})

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
