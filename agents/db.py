"""
db.py — SQLite database utility for submissions, findings, and job tracking.

Schema
------
submissions : stores raw code + language per job
jobs        : tracks pipeline stage + per-agent status
findings    : analysis results
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from agents.models import Finding, Severity

DB_FILE = Path(__file__).parent.parent / "db.sqlite3"


def get_db_connection() -> sqlite3.Connection:
    """Return a connection to the SQLite database."""
    conn = sqlite3.connect(str(DB_FILE), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # Allow concurrent reads
    return conn


def init_db() -> None:
    """Initialize the SQLite schema (idempotent)."""
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS submissions (
                id TEXT PRIMARY KEY,
                code TEXT NOT NULL,
                language TEXT NOT NULL,
                filename TEXT NOT NULL DEFAULT 'untitled',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                submission_id TEXT NOT NULL,
                stage TEXT NOT NULL DEFAULT 'analysis',
                agent_analysis TEXT NOT NULL DEFAULT 'queued',
                agent_security TEXT NOT NULL DEFAULT 'queued',
                agent_remediation TEXT NOT NULL DEFAULT 'queued',
                agent_summary TEXT NOT NULL DEFAULT 'queued',
                error TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (submission_id) REFERENCES submissions (id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submission_id TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                line_start INTEGER NOT NULL,
                line_end INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                source_agent TEXT NOT NULL,
                extra TEXT NOT NULL,
                fix TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (submission_id) REFERENCES submissions (id) ON DELETE CASCADE
            )
            """
        )
        # Migrate: add fix column if it doesn't exist (for existing DBs)
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN fix TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass
        # Migrate: add filename column if it doesn't exist
        try:
            conn.execute("ALTER TABLE submissions ADD COLUMN filename TEXT NOT NULL DEFAULT 'untitled'")
        except Exception:
            pass
        conn.commit()


# ---------------------------------------------------------------------------
# Submission helpers
# ---------------------------------------------------------------------------

def save_submission(code: str, language: str, filename: str = "untitled") -> str:
    """Save code submission and return a unique submission ID."""
    init_db()
    sub_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO submissions (id, code, language, filename, created_at) VALUES (?, ?, ?, ?, ?)",
            (sub_id, code, language, filename, now),
        )
        conn.commit()
    return sub_id


def get_submission(submission_id: str) -> tuple[str, str, str] | None:
    """Retrieve (code, language, filename) for a submission ID, or None if not found."""
    init_db()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT code, language, filename FROM submissions WHERE id = ?", (submission_id,)
        ).fetchone()
        if row:
            return row["code"], row["language"], row["filename"]
    return None


# ---------------------------------------------------------------------------
# Job helpers
# ---------------------------------------------------------------------------

def create_job(submission_id: str) -> str:
    """Create a new job record and return the job ID."""
    init_db()
    job_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO jobs
               (id, submission_id, stage, agent_analysis, agent_security,
                agent_remediation, agent_summary, created_at)
               VALUES (?, ?, 'analysis', 'queued', 'queued', 'queued', 'queued', ?)""",
            (job_id, submission_id, now),
        )
        conn.commit()
    return job_id


def update_job(job_id: str, **kwargs: Any) -> None:
    """Update arbitrary fields on a job row."""
    if not kwargs:
        return
    set_clauses = ", ".join(f"{k} = ?" for k in kwargs)
    values = list(kwargs.values()) + [job_id]
    with get_db_connection() as conn:
        conn.execute(f"UPDATE jobs SET {set_clauses} WHERE id = ?", values)
        conn.commit()


def get_job(job_id: str) -> dict[str, Any] | None:
    """Retrieve a job dict by ID."""
    init_db()
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row:
            return dict(row)
    return None


# ---------------------------------------------------------------------------
# Findings helpers
# ---------------------------------------------------------------------------

def save_findings(submission_id: str, findings: list[Finding]) -> None:
    """Save a list of merged findings (with optional fix field)."""
    init_db()
    with get_db_connection() as conn:
        conn.execute("DELETE FROM findings WHERE submission_id = ?", (submission_id,))
        for f in findings:
            fix = f.extra.pop("fix", "") if isinstance(f.extra, dict) else ""
            conn.execute(
                """
                INSERT INTO findings (
                    submission_id, type, severity, line_start, line_end,
                    title, description, category, source_agent, extra, fix
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    submission_id,
                    f.type,
                    f.severity.value,
                    f.line_start,
                    f.line_end,
                    f.title,
                    f.description,
                    f.category,
                    f.source_agent,
                    json.dumps(f.extra),
                    fix,
                ),
            )
        conn.commit()


def get_findings(submission_id: str) -> list[dict[str, Any]]:
    """Retrieve all findings as dicts (includes fix field)."""
    init_db()
    rows = []
    with get_db_connection() as conn:
        raw = conn.execute(
            "SELECT * FROM findings WHERE submission_id = ?", (submission_id,)
        ).fetchall()
        for r in raw:
            rows.append(dict(r))
    return rows
