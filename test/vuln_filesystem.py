"""Intentionally vulnerable: FILESYSTEM, PATH_TRAVERSAL, SSRF sinks."""
import os
import shutil
import requests
from flask import Flask, request
from pathlib import Path

app = Flask(__name__)
BASE_DIR = "/var/app/uploads"


# PATH_TRAVERSAL: os.path.join with filename from user
@app.route("/download")
def download_file():
    filename = request.args.get("filename")  # SOURCE: HTTP input
    path = os.path.join(BASE_DIR, filename)  # SINK: path traversal — ../../../etc/passwd
    with open(path, "r") as f:
        return f.read()


# FILESYSTEM: write to user-controlled path
@app.route("/upload", methods=["POST"])
def upload():
    filename = request.form.get("filename")  # SOURCE
    content = request.form.get("content")
    out_path = os.path.join(BASE_DIR, filename)
    with open(out_path, "w") as f:  # SINK: open() write with user-controlled path
        f.write(content)
    return "ok"


# FILESYSTEM: shutil.rmtree with user input
@app.route("/delete_project", methods=["DELETE"])
def delete_project():
    project_name = request.args.get("project")  # SOURCE
    project_dir = os.path.join(BASE_DIR, project_name)
    shutil.rmtree(project_dir)  # SINK: recursive delete without auth
    return "deleted"


# SSRF: requests.get with user-controlled URL
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")  # SOURCE: user-controlled URL
    resp = requests.get(url)  # SINK: SSRF
    return resp.text


# SSRF: internal service proxy with user-controlled host
@app.route("/proxy")
def proxy():
    host = request.args.get("host")
    port = request.args.get("port", "80")
    url = f"http://{host}:{port}/api/internal"
    response = requests.post(url, json={"action": "status"})  # SINK: SSRF to internal
    return response.text


# PATH_TRAVERSAL: pathlib / operator
@app.route("/read")
def read_file():
    user_path = request.args.get("path")  # SOURCE
    full_path = Path(BASE_DIR) / user_path  # SINK: pathlib traversal
    return full_path.read_text()


# FILESYSTEM: os.rename with user input (dest)
@app.route("/rename", methods=["POST"])
def rename_file():
    src = request.form.get("src")
    dst = request.form.get("dst")  # SOURCE
    os.rename(os.path.join(BASE_DIR, src), os.path.join(BASE_DIR, dst))  # SINK
    return "renamed"
