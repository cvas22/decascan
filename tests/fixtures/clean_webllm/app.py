import hashlib
import logging
import os
import secrets
import subprocess
from pathlib import Path

import requests
import torch
import yaml
from flask import Flask, abort, request, send_from_directory
from openai import OpenAI

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
client = OpenAI()
logger = logging.getLogger(__name__)
BASE = Path("/srv/files").resolve()
ALLOWED = {"https://api.example.com/data"}


@app.route("/chat")
def chat():
    question = request.args["q"]
    reply = client.chat.completions.create(
        model="gpt-4o",
        max_tokens=512,
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": question},
        ],
    )
    return reply.choices[0].message.content


@app.route("/file")
def file():
    target = (BASE / "report.pdf").resolve()
    if not target.is_relative_to(BASE):
        abort(404)
    return send_from_directory(BASE, "report.pdf")


def helpers(cursor, uid, blob, password):
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
    hashlib.sha256(password.encode()).hexdigest()
    token = secrets.token_urlsafe(32)
    yaml.safe_load(blob)
    requests.get("https://api.example.com/data", timeout=5)
    logger.info("login for user %s", uid)
    subprocess.run(["ls", "-l"], check=True)
    torch.load("model.bin", weights_only=True)
    return token
