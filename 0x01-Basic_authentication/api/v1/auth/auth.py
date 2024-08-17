#!/usr/bin/env python3
""" Authentication Module """
from flask import request
from typing import List, TypeVar


class Auth:
    """ API Authentication Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """will be defined later"""
        return False

    def authorization_header(self, request=None) -> str:
        """ handles authorization header """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Validates current user """
        return None
