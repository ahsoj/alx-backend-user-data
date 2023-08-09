#!/usr/bin/env python3
"""Session auth module.
"""

from uuid import uuid4

from models.user import User

from .auth import Auth


class SessionAuth(Auth):
    """Session authentication implementation."""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Create a new session id for a user_id"""
        if not user_id or isinstance(user_id, str):
            return None
        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """get user ID by session id"""
        if not session_id or isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """return User instance based on a cookie value"""
        user_id = self.user_id_for_session_id(self.session_cookie(request))
        return User.get(user_id)

    def destroy_session(self, request=None):
        """Destroys an authenticated session."""
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if (not request or not session_id) or not user_id:
            return False
        if session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
        return True
