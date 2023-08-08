#!/usr/bin/env python3
"""
Authentication module for the API
"""

from flask import request
from typing import List, TypeVar


class Auth:
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """return Flase"""
        return False

    def authorization_header(self, request=None) -> str:
        """request: the flask request object
        return None
        """
        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """request: the flask request object
        return None
        """
        return None
