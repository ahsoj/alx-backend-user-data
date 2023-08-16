#!/usr/bin/env python3
""" Test module.
"""

import requests


def register_user(email: str, password: str) -> None:
    """Test user registration"""
    url = "http://0.0.0.0:5000/users"
    credential = {"email": email, "password": password}
    result = requests.post(url, data=credential)
    assert result.status_code == 200
    assert result.json() == {"email": email, "message": "user created"}
    result = requests.post(url, data=credential)
    assert result.status_code == 400
    assert result.json() == {"message": "email already registered"}


def log_in_wrong_password(email: str, password: str) -> None:
    """Test login attempt with wrong password"""
    url = "http://0.0.0.0:5000/sessions"
    credential = {"email": email, "password": password}
    result = requests.post(url, data=credential)
    assert result.status_code == 401


def log_in(email: str, password: str) -> str:
    """Test successful login"""
    url = "http://0.0.0.0:5000/sessions"
    credential = {"email": email, "password": password}
    result = requests.post(url, data=credential)
    assert result.status_code == 200
    assert result.json() == {"email": email, "message": "logged in"}
    return result.cookies.get("session_id")


def profile_unlogged() -> None:
    """attempt to get profile info while logged out"""
    url = "http://0.0.0.0:5000/profile"
    result = requests.get(url)
    assert result.status_code == 403


def profile_logged(session_id: str) -> None:
    """attempt to get profile info while logged in"""
    url = "http://0.0.0.0:5000/profile"
    cookies = {"session_id": session_id}
    result = requests.get(url, cookies=cookies)
    assert result.status_code == 200
    assert "email" in result.json()


def log_out(session_id: str) -> None:
    """Test logout"""
    url = "http://0.0.0.0:5000/sessions"
    cookies = {"session_id": session_id}
    result = requests.delete(url, cookies=cookies)
    assert result.status_code == 200
    assert result.json() == {"message": "Bienvenue"}


def reset_password_token(email: str) -> str:
    """Test resetting password token"""
    url = "http://0.0.0.0:5000/reset_password"
    credential = {"email": email}
    result = requests.post(url, data=credential)
    assert result.status_code == 200
    assert "email" in result.json()
    assert result.json()["email"] == email
    assert "reset_token" in result.json()
    return result.json().get("reset_token")


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Test updating user password"""
    url = "http://0.0.0.0:5000/reset_password"
    credential = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password,
    }
    result = requests.put(url, data=credential)
    assert result.status_code == 200
    assert result.json() == {"email": email, "message": "Password updated"}


if __name__ == "__main__":
    EMAIL = "guillaume@holberton.io"
    PASSWD = "b4l0u"
    NEW_PASSWD = "t4rt1fl3tt3"

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
