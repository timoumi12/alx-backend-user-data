#!/usr/bin/env python3
"""flassk app"""
import logging
from flask import Flask, abort, jsonify, redirect, request
from auth import Auth

logging.disable(logging.WARNING)

AUTH = Auth()
app = Flask(__name__)


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """returns json payload"""
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
