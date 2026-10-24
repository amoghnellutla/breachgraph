# INTENTIONALLY VULNERABLE: demo target for breachgraph. Never deploy.
# This service is internet-facing (behind a k8s Ingress) and has an SSRF route. The pod runs
# with hostNetwork, so SSRF reaches the node's cloud metadata endpoint and steals the node
# IAM role's credentials -> which can read the customer-data S3 bucket. breachgraph should find
# that whole chain as one attack path.
import os

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/health")
def health():
    return "ok"


@app.route("/fetch")
def fetch():
    # SSRF: the URL comes straight from the user, no allowlist.
    url = request.args.get("url", "")
    return requests.get(url, timeout=5).text


@app.route("/thumbnail")
def thumbnail():
    # Command injection: user input flows into a shell.
    image = request.args.get("src", "")
    return os.popen("convert " + image + " -resize 100x100 /tmp/out.png").read()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
