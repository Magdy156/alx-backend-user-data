#!/usr/bin/env python3
""" Returns a salted, hashed password, byte in string """
import bcrypt


def hash_password(password: str) -> bytes:
    """ encrypt the password"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ compare 2 passwords"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
