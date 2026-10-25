import hashlib
import logging
import os
import pickle
import random
import subprocess

import requests
import torch
import yaml
from flask import Flask, request, send_file
from langchain_experimental.tools import PythonREPLTool
from openai import OpenAI
from transformers import AutoModel

app = Flask(__name__)
app.secret_key = "hunter2-prod-signing-key-9f3a"
client = OpenAI()
logger = logging.getLogger(__name__)
DEBUG = True


@app.route("/chat")
def chat():
    question = request.args["q"]
    reply = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": f"You are a bot. User asked: {question}"},
            {"role": "user", "content": question},
        ],
    )
    answer = reply.choices[0].message.content
    eval(answer)
    return answer


@app.route("/file")
def file():
    name = request.args["name"]
    return send_file(name)


@app.route("/user")
def user(cursor):
    uid = request.args["id"]
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    os.system("ping " + uid)
    return requests.get(request.args["url"]).text


def helpers(blob, password):
    hashlib.md5(password.encode()).hexdigest()
    token = random.randint(0, 999999)
    pickle.loads(blob)
    yaml.load(blob)
    requests.get("https://internal", verify=False)
    logger.info("login for %s with %s", "bob", password)
    subprocess.run(f"ls {blob}", shell=True)
    torch.load("model.bin")
    AutoModel.from_pretrained("someorg/some-model", trust_remote_code=True)
    tools = [PythonREPLTool()]
    return token, tools


def risky():
    raise RuntimeError


def swallow():
    try:
        risky()
    except Exception:
        pass
