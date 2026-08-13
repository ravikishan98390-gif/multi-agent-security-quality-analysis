"""
hardcoded_secret.py — Planted hardcoded credential vulnerability fixture.

Planted issues (4 variants):
  Line 19 — DB_PASSWORD literal in module config                    [CRITICAL]
  Line 20 — API_KEY literal at module level                         [CRITICAL]
  Line 21 — JWT_SECRET hardcoded string                             [CRITICAL]
  Line 22 — AWS_SECRET_ACCESS_KEY hardcoded                         [CRITICAL]
"""

import os
import sqlite3
import hmac
import hashlib

# ── Planted Issues #1–4: Hardcoded Credentials ────────────────────────────
DB_PASSWORD = "Sup3rS3cr3t!2024"          # line 19 — VULNERABILITY: plaintext password
API_KEY = "sk-live-abcdef1234567890xyz"   # line 20 — VULNERABILITY: live API key in source
JWT_SECRET = "my-jwt-signing-secret-key"  # line 21 — VULNERABILITY: signing secret exposed
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # line 22


def connect_db():
    # Uses the plaintext password hardcoded above — never safe to ship
    return sqlite3.connect(f"file:app.db?password={DB_PASSWORD}", uri=True)


def verify_token(token: str) -> bool:
    # Uses hardcoded JWT secret — any token can be forged if this leaks
    expected = hmac.new(JWT_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, token)


def upload_to_s3(bucket: str, key: str, data: bytes) -> None:
    import boto3
    # Uses hardcoded AWS key — gives attacker full AWS access if this file leaks
    s3 = boto3.client(
        "s3",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    s3.put_object(Bucket=bucket, Key=key, Body=data)


# ── Clean reference — credentials loaded from environment (should NOT flag) ─
SAFE_PASSWORD = os.environ.get("DB_PASSWORD", "")
SAFE_API_KEY = os.environ.get("API_KEY", "")
