#!/usr/bin/env python3
"""Filter module"""
import re
from typing import List
import logging


PII_FIELDS = ("name", "email", "password", "ssn", "phone")


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
        """ Returns filtered values """
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)


def filter_datum(
        fields: List[str],
        redaction: str, message: str, separator: str) -> str:
    """Fileter func"""
    for field in fields:
        message = re.sub(
            f'{field}=(.*?){separator}',
            f'{field}={redaction}{separator}', message)
    return message


def get_logger() -> logging.Logger:
    """ Returns a Logger Object """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    logger.addHandler(stream_handler)

    return logger
