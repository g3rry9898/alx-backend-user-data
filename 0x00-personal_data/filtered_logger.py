#!/usr/bin/env python3
"""
This module provides a Redacting Formatter for logging, a logger setup, and a function to connect to a secure Holberton database.
"""

import logging
import os
import mysql.connector
from typing import List, Tuple
from mysql.connector import connection

PII_FIELDS: Tuple[str, ...] = ("name", "email", "phone", "ssn", "password")

def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Returns the log message obfuscated.
    
    Args:
        fields (List[str]): List of strings representing all fields to obfuscate.
        redaction (str): String representing by what the field will be obfuscated.
        message (str): String representing the log line.
        separator (str): String representing by which character is separating all fields in the log line.
    
    Returns:
        str: The obfuscated log message.
    """
    pattern = f"({'|'.join(fields)})=[^{separator}]*"
    return re.sub(pattern, lambda m: f"{m.group(1)}={redaction}", message)

class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Formats the log record by obfuscating specified fields.
        
        Args:
            record (logging.LogRecord): The log record to format.
        
        Returns:
            str: The formatted log record.
        """
        return filter_datum(self.fields, self.REDACTION, super().format(record), self.SEPARATOR)

def get_logger() -> logging.Logger:
    """
    Creates and returns a logger named 'user_data' with a StreamHandler
    and RedactingFormatter.
    
    Returns:
        logging.Logger: Configured logger.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream
