#!/usr/bin/env python3
"""
Route module for the API
"""
import os
from os import getenv

from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.session_db_auth import SessionDBAuth
from api.v1.auth.session_exp_auth import SessionExpAuth
from api.v1.views import app_views
from flask import Flask, abort, jsonify, request
from flask_cors import CORS, cross_origin

app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

auth = None
auth_type = getenv("AUTH_TYPE", "auth")
if auth_type == "auth":
    auth = Auth()
if auth_type == "basic_auth":
    auth = BasicAuth()
if auth_type == "session_auth":
    auth = SessionAuth()
if auth_type == "session_exp_auth":
    auth = SessionExpAuth()
if auth_type == "session_db_auth":
    auth = SessionDBAuth()


@app.before_request
def authenticate_user():
    """Authenticate before any request"""
    paths = [
        "/api/v1/status/",
        "/api/v1/unauthorized/",
        "/api/v1/forbidden/",
        "/api/v1/auth_session/login/",
    ]
    if auth:
        if auth.require_auth(request.path, paths):
            current_user = auth.current_user(request)
            if not auth.authorization_header(request) and not auth.session_cookie(
                request
            ):
                abort(401)
            if not current_user:
                abort(403)
            request.current_user = current_user


@app.errorhandler(401)
def unauthorized(error) -> str:
    """Unauthorized error handler"""
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def unauthorized(error) -> str:
    """Forbidden error handler"""
    return jsonify({"error": "Forbidden"}), 403


@app.errorhandler(404)
def not_found(error) -> str:
    """Not found handler"""
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
