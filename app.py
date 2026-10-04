import hashlib
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

# VULN 1 : secret en dur (Bandit B105)
SECRET_KEY = "super-secret-password-123"
app.config["SECRET_KEY"] = SECRET_KEY


def get_db():
    conn = sqlite3.connect("users.db")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, name TEXT, password TEXT)"
    )
    return conn


@app.route("/")
def index():
    return "Bienvenue sur l'application du TP securite"


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    # VULN 2 : injection SQL (Bandit B608)
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    rows = get_db().execute(query).fetchall()
    return str(rows)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # VULN 3 : XSS reflechi (entree utilisateur renvoyee en HTML brut)
    return "<h1>Bonjour " + name + "</h1>"


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    # VULN 4 : eval sur entree utilisateur (Bandit B307)
    return str(eval(expr))


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN 5 : injection de commande, shell=True (Bandit B602)
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


@app.route("/hash")
def hash_password():
    pwd = request.args.get("pwd", "")
    # VULN 6 : hash faible MD5 (Bandit B324)
    return hashlib.md5(pwd.encode()).hexdigest()


@app.route("/config", methods=["POST"])
def load_config():
    # VULN 7 : deserialisation YAML non sure (Bandit B506)
    data = yaml.load(request.data, Loader=yaml.Loader)
    return str(data)


if __name__ == "__main__":
    # VULN 8 : debug actif + ecoute sur toutes les interfaces (B201 / B104)
    app.run(host="0.0.0.0", port=5000, debug=True)