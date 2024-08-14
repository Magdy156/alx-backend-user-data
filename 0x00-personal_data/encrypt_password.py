#!/usr/bin/env python3
""" Returns a salted, hashed password, byte in string """
import bcrypt


def hash_password(password: str) -> bytes:
    """ encrypt the password"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
