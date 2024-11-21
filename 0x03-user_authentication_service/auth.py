#!/usr/bin/env python3
"""
Auth module for authentication operations
"""
import bcrypt

class Auth:
    """
    Auth class to interact with the authentication database.
    """
    def _hash_password(self, password: str) -> bytes:
        """
        Hash a password
        """
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

