import sqlite3

conn = sqlite3.connect("licenses.db")
c = conn.cursor()

c.execute("DROP TABLE IF EXISTS LICENSES")
c.execute("DROP TABLE IF EXISTS ACTIVATIONS")

c.execute("""
CREATE TABLE LICENSES (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT UNIQUE,
    max_ativacoes INTEGER,
    ativacoes_usadas INTEGER DEFAULT 0,
    ativo INTEGER DEFAULT 1
)
""")
c.execute("""
CREATE TABLE ACTIVATIONS (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    hwid TEXT,
    data TEXT,
    ip TEXT
)
""")
conn.commit()
conn.close()
print("Banco criado!")
