#!/usr/bin/env python3
"""
Authentication module for the API
"""

import fnmatch
from typing import List, TypeVar

from flask import request


class Auth:
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """return Flase"""
        if path is None or excluded_paths is None or not excluded_paths:
            return True
        for excluded_path in excluded_paths:
            if fnmatch.fnmatch(path, excluded_path):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """request: the flask request object
        return None
        """
        if request is None or not request.headers.get("Authorization"):
            return None
        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar("User"):
        """request: the flask request object
        return None
        """
        return None
