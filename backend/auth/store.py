"""
Minimal local user store (SQLite), per SRS Section 2.4 (SQLite local data store).

Only ever stores: username, bcrypt password_hash, created_at.
No plaintext password ever touches this module.
"""
import datetime
import sqlite3
from contextlib import contextmanager

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


@contextmanager
def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with _conn() as conn:
        conn.execute(_SCHEMA)


def has_any_user() -> bool:
    with _conn() as conn:
        row = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        return row is not None


def get_user(username: str):
    with _conn() as conn:
        return conn.execute(
            "SELECT username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()


def create_user(username: str, password_hash: str):
    with _conn() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, datetime.datetime.now(datetime.timezone.utc).isoformat()),
        )
