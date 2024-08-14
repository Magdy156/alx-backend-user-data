#!/usr/bin/env python3
"""Filter module"""
import re
from typing import List
import logging
import os
import mysql.connector


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


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ Connection to MySQL """
    db_connect = mysql.connector.connect(
        user=os.getenv('PERSONAL_DATA_DB_USERNAME', 'root'),
        password=os.getenv('PERSONAL_DATA_DB_PASSWORD', ''),
        host=os.getenv('PERSONAL_DATA_DB_HOST', 'localhost'),
        database=os.getenv('PERSONAL_DATA_DB_NAME')
    )
    return db_connect


def main() -> None:
    """ tain a database connection using get_db and retrieve all
    rows in the users table and display each row under a filtered format
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    colNames = [field[0] for field in cursor.description]
    logger = get_logger()

    for row in cursor:
        loggedInfo = ''
        for r, col in zip(row, colNames):
            loggedInfo += f'{col}={(r)}; '
        logger.info(loggedInfo)

    cursor.close()
    db.close()


if __name__ == '__main__':
    main()
