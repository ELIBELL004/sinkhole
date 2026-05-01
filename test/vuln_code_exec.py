"""Intentionally vulnerable: CODE_EXEC, DESERIALIZATION, COMMAND_EXEC sinks."""
import pickle
import subprocess
import os
import torch
import joblib
import yaml
import marshal


# CODE_EXEC: eval with user input
def run_user_formula(user_input):
    result = eval(user_input)  # SINK: eval() with user input
    return result


# CODE_EXEC: exec with HTTP form data
from flask import Flask, request
app = Flask(__name__)

@app.route("/run", methods=["POST"])
def run_code():
    code = request.form.get("code")
    exec(code)  # SINK: exec() with HTTP input


# DESERIALIZATION: pickle.loads with raw user data
@app.route("/load_model", methods=["POST"])
def load_model():
    data = request.data
    obj = pickle.loads(data)  # SINK: pickle.loads with HTTP body
    return str(obj)


# DESERIALIZATION: torch.load without weights_only
def load_torch_model(model_path):
    model = torch.load(model_path)  # SINK: torch.load without weights_only=True
    return model


# DESERIALIZATION: joblib
def restore_pipeline(path):
    pipeline = joblib.load(path)  # SINK: joblib.load (pickle under the hood)
    return pipeline


# COMMAND_EXEC: os.system with user input
@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system(f"ping {host}")  # SINK: os.system with user-controlled host


# COMMAND_EXEC: subprocess with shell=True
def run_script(user_script):
    subprocess.run(user_script, shell=True)  # SINK: subprocess + shell=True


# DESERIALIZATION: yaml.load without SafeLoader
def parse_config(config_str):
    cfg = yaml.load(config_str)  # SINK: yaml.load without Loader


# DESERIALIZATION: marshal.loads
def load_bytecode(user_bytes):
    code = marshal.loads(user_bytes)  # SINK: marshal.loads
