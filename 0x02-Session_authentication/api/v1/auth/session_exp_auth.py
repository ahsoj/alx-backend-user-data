#!/usr/bin/env python3
"""Session authentication with expiration
"""

from datetime import datetime, timedelta
from os import getenv

from flask import request

from .session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """add an expiration date to a Session ID"""

    def __init__(self) -> None:
        """Initialize"""
        super().__init__()
        try:
            self.sesison_duration = int(getenv("SESSION_DURATION", "0"))
        except Exception:
            self.sesison_duration = 0

    def create_session(self, user_id=None):
        """Create a session ID"""
        session_id = super().create_session(user_id)
        if not isinstance(session_id, str):
            return None
        self.user_id_by_session_id[session_id] = {
            "user_id": user_id,
            "created_at": datetime.now(),
        }
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """retrieve the user id with session id"""
        if session_id in self.user_id_by_session_id:
            _session_id = self.user_id_by_session_id[session_id]
            if self.sesison_duration <= 0:
                return _session_id["user_id"]
            if "created_at" in _session_id:
                current_time = datetime.now()
                time_span = timedelta(seconds=self.sesison_duration)
                exp_time = _session_id["created_at"] + time_span
                if exp_time > current_time:
                    return _session_id["user_id"]
        return None
