#!/usr/bin/env python3
"""
This module provides functions to hash passwords and validate them.
"""

import bcrypt

def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.
    
    Args:
        password (str): The password to hash.
    
    Returns:
        bytes: The salted, hashed password.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates that the provided password matches the hashed password.
    
    Args:
        hashed_password (bytes): The hashed password.
        password (str): The password to validate.
    
    Returns:
        bool: True if the password matches the hashed password, False otherwise.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)

