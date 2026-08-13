"""
sqli_python.py — Planted SQL Injection vulnerability fixture.

Planted issues (3 variants):
  Line 21 — f-string SQL query fed directly to db.execute()          [CRITICAL]
  Line 30 — string concatenation SQL query via + operator             [CRITICAL]
  Line 38 — .format() interpolation into a raw SQL string             [CRITICAL]
"""

import sqlite3

DB_PATH = "app.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


# ── Planted Issue #1: f-string SQL Injection ───────────────────────────────
def get_user_by_name(username: str):
    conn = get_connection()
    # VULNERABILITY: f-string injects untrusted `username` directly into SQL
    query = f"SELECT * FROM users WHERE username = '{username}'"   # line 21
    return conn.execute(query).fetchall()


# ── Planted Issue #2: String Concatenation SQL Injection ───────────────────
def delete_record(table: str, record_id: str):
    conn = get_connection()
    # VULNERABILITY: user-controlled `record_id` concatenated into query string
    query = "DELETE FROM " + table + " WHERE id = " + record_id    # line 30
    conn.execute(query)
    conn.commit()


# ── Planted Issue #3: .format() SQL Injection ──────────────────────────────
def update_email(user_id: str, new_email: str):
    conn = get_connection()
    # VULNERABILITY: .format() interpolates user data into SQL without escaping
    query = "UPDATE users SET email = '{}' WHERE id = {}".format(new_email, user_id)  # line 38
    conn.execute(query)
    conn.commit()


# ── Clean reference — parameterized query (should NOT be flagged) ──────────
def safe_get_user(user_id: int):
    conn = get_connection()
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
