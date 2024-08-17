#!/usr/bin/env python3
""" Authentication Module """
from flask import request
from typing import List, TypeVar


class Auth:
    """ API Authentication Class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ returns True if the path is not in
        the list of strings excluded_paths
        """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True

        pathLength = len(path)
        if pathLength == 0:
            return True

        if path[pathLength - 1] == '/':
            slash_path = True
        else:
            slash_path = False

        tmp_path = path
        if not slash_path:
            tmp_path += '/'

        for pathe in excluded_paths:
            pathLength = len(pathe)
            if pathLength == 0:
                continue

            if pathe[pathLength - 1] != '*':
                if tmp_path == pathe:
                    return False
            else:
                if pathe[:-1] == pathe[:pathLength - 1]:
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """ handles authorization header """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Validates current user """
        return None
