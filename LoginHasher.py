import sqlite3
import secrets
import hashlib
import logging
from typing import Optional

class Login_Hasher:
    """
    A class to handle user authentication and password hashing using SQLite database.

    Attributes:
        db_file (str): The name of the SQLite database file.
        conn (Optional[sqlite3.Connection]): Connection to the SQLite database.
    """

    def __init__(self, db_file: str) -> None:
        """
        Initializes the Database class with the given database file.

        Args:
            db_file (str): The name of the SQLite database file.
        """
        self.db_file = db_file
        self.conn = self.create_connection()
        self.logger = logging.getLogger(__name__)  # Create logger

    def create_connection(self) -> Optional[sqlite3.Connection]:
        """
        Creates a connection to the SQLite database.

        Returns:
            Optional[sqlite3.Connection]: Connection to the database or None in case of error.
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            self.create_table(conn)  # Creating the table after establishing the connection
            return conn
        except sqlite3.Error as e:
            self.logger.error(e)
        return conn

    def create_table(self, conn: sqlite3.Connection) -> None:
        """
        Creates the users table in the database if it doesn't exist.

        Args:
            conn (sqlite3.Connection): Connection to the database.
        """
        sql_create_table = """CREATE TABLE IF NOT EXISTS users (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                login TEXT NOT NULL UNIQUE,
                                hashed_password TEXT NOT NULL,
                                salt TEXT NOT NULL
                            );"""
        try:
            c = conn.cursor()
            c.execute(sql_create_table)
        except sqlite3.Error as e:
            self.logger.error(e)

    def add_user(self, login: str, password: str) -> None:
        """
        Adds a user to the database.

        Args:
            login (str): User's login name.
            password (str): User's password.
        """
        # Check if the login is already taken
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) FROM users WHERE login=?", (login,))
        result = c.fetchone()
        if result and result[0] > 0:
            self.logger.info("Login is already taken.")  # Log message at INFO level
            return None

        # Proceed with adding the user if login is not taken
        salt = secrets.token_hex(16)  # Generating a random salt
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(),
                                              100000)  # Hashing the password with PBKDF2
        sql_insert_user = "INSERT INTO users (login, hashed_password, salt) VALUES (?, ?, ?)"
        try:
            c.execute(sql_insert_user, (login, hashed_password.hex(), salt))
            self.conn.commit()
            self.logger.info("User has been added to the database.")  # Log message at INFO level
        except sqlite3.Error as e:
            self.logger.error(e)

    def verify_login(self, login: str, password: str) -> bool:
        """
        Verifies login credentials.

        Args:
            login (str): User's login name.
            password (str): User's password.
        """
        c = self.conn.cursor()
        c.execute("SELECT hashed_password, salt FROM users WHERE login=?", (login,))
        result = c.fetchone()
        if result:
            hashed_password, salt = result
            input_hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
            if input_hashed_password == hashed_password:
                return True
            else:
                return False
        else:
            return False

    def close_connection(self) -> None:
        """
        Closes connection to the database.
        """
        if self.conn:
            self.conn.close()
