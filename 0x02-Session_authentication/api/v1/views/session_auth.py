#!/usr/bin/env python3
"""Session route modlue.
"""

from os import getenv
from typing import Tuple

from flask import abort, jsonify, request
from models.user import User

from . import app_views


@app_views.route("/auth_session/login", methods=["POST"], strict_slashes=False)
def login() -> Tuple[str, int]:
    """ "login route"""
    email = request.form.get("email")
    password = request.form.get("password")
    if not email or len(email.strip()) == 0:
        return jsonify({"error": "email missing"}), 400
    if not password or len(password.strip()) == 0:
        return jsonify({"error": "password missing"}), 400

    try:
        users = User.search({"email": email})
    except:
        return jsonify({"error": "no user found for this email"}), 404

    if len(users) <= 0:
        return jsonify({"error": "no user found for this email"}), 404
    if users[0].is_valid_password(password):
        from api.v1.app import auth

        sessiond_id = auth.create_session(getattr(users[0], "id"))
        res = jsonify(users[0].to_json())
        res.set_cookie(getenv("SESSION_NAME"), sessiond_id)
        return res
    return jsonify({"error": "wrong password"}), 401


@app_views.route("/auth_session/logout", methods=["DELETE"], strict_slashes=False)
def logout() -> Tuple[str, int]:
    """logout/delete route."""
    from api.v1.app import auth

    is_destroyed = auth.destroy_session(request)
    if not is_destroyed:
        abort(404)
    return jsonify({})
