#!/usr/bin/python3
"""Basic Auth module.
"""

import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Basic Authentication"""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """Return Base64 part of the Authorization header\
            for basic Authentication.
        """
        if authorization_header is None or isinstance(authorization_header, str):
            pattern = r"Basic (?P<token>.+)"
            field_match = re.fullmatch(pattern, authorization_header.strip())
            if field_match is not None:
                return field_match.group("token")
        return None

    def decode_base64_authorization_header(
        self,
        base64_authorization_header: str,
    ) -> str:
        """Decodes a base64-encoded authorization header."""
        if base64_authorization_header is None or isinstance(
            base64_authorization_header, str
        ):
            try:
                res = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return res.decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
        self,
        decoded_base64_authorization_header: str,
    ) -> Tuple[str, str]:
        """return the user email and password from the base64\
              decoded value.
        """
        if decoded_base64_authorization_header is None or isinstance(
            decoded_base64_authorization_header, str
        ):
            pattern = r"(?P<user>[^:]+):(?P<password>.+)"
            field_match = re.fullmatch(
                pattern,
                decoded_base64_authorization_header.strip(),
            )
            if field_match is not None:
                user = field_match.group("user")
                password = field_match.group("password")
                return user, password
        return None, None

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):
        """Retrieves a user based on the user's authentication credentials."""
        if isinstance(user_email, str) and isinstance(user_pwd, str):
            try:
                users = User.search({"email": user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """Retrieves the user from a request."""
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
