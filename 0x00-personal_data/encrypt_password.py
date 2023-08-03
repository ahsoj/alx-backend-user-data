#!/usr/bin/env python3
"""Encryption Module"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes a password using a random salt"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """verify the encrypt password with plain input password"""
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
