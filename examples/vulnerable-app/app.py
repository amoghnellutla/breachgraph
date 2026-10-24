# INTENTIONALLY VULNERABLE: demo target for breachgraph. Never deploy.
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-do-not-use"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection: user input concatenated into the query
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    return str(cursor.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # OS command injection: shell=True with user input
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/fetch")
def fetch():
    # SSRF: server fetches any URL the client supplies
    url = request.args.get("url")
    return requests.get(url, timeout=5).text


@app.route("/restore", methods=["POST"])
def restore():
    # Insecure deserialization of untrusted input
    session = pickle.loads(request.data)
    return str(session)


@app.route("/config", methods=["POST"])
def load_config():
    # Unsafe YAML load allows arbitrary object construction
    return str(yaml.load(request.data, Loader=yaml.Loader))


@app.route("/read")
def read_file():
    # Path traversal
    name = request.args.get("name")
    with open(os.path.join("/var/data", name)) as fh:
        return fh.read()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
