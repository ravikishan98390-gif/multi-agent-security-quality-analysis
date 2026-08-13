"""
test_orchestrator.py — Integration tests for Orchestrator and FastAPI endpoints.
"""

from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

from app import app
from agents.db import get_submission, get_findings, save_submission, DB_FILE
from agents.orchestrator import analyze_submission
from agents.models import Severity

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_db():
    """Ensure db is clean before and after each test."""
    if DB_FILE.exists():
        try:
            os.remove(DB_FILE)
        except OSError:
            pass
    yield
    if DB_FILE.exists():
        try:
            os.remove(DB_FILE)
        except OSError:
            pass


def test_db_crud_operations():
    code = "def test(): pass"
    lang = "python"
    
    sub_id = save_submission(code, lang)
    assert sub_id is not None
    
    fetched = get_submission(sub_id)
    assert fetched is not None
    assert fetched[0] == code
    assert fetched[1] == lang


def test_api_submit_valid_code():
    response = client.post(
        "/submissions",
        json={"code": "def hello():\n    print('world')", "language": "python"}
    )
    assert response.status_code == 201
    data = response.json()
    assert "submission_id" in data
    
    # Retrieve from DB to check if persisted
    sub_id = data["submission_id"]
    fetched = get_submission(sub_id)
    assert fetched is not None
    assert "hello" in fetched[0]


def test_api_submit_invalid_python_syntax():
    # Intentionally missing colon in Python function def
    response = client.post(
        "/submissions",
        json={"code": "def hello()\n    print('world')", "language": "python"}
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "Syntax validation failed" in detail


def test_api_submit_invalid_java_syntax():
    # Intentionally invalid Java syntax (missing class/brackets)
    response = client.post(
        "/submissions",
        json={"code": "public void hello() {", "language": "java"}
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "Syntax validation failed" in detail


@pytest.mark.asyncio
async def test_orchestrator_runs_concurrently(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    code = """
def check_user(username):
    # Planted SQL Injection
    query = f"SELECT * FROM users WHERE name = '{username}'"
    db.execute(query)
    
    # Planted code smell: naming
    temp = 1
"""
    sub_id = save_submission(code, "python")
    findings = await analyze_submission(sub_id)
    
    # Verify both quality (code smell) and security findings are present
    cats = {f.category for f in findings}
    assert "sql_injection" in cats
    assert "poor_naming" in cats
    
    # Verify sorting: severity ascending (CRITICAL / HIGH first), then line_start
    severities = [f.severity for f in findings]
    # Check that it's sorted
    assert severities == sorted(severities)


def test_api_analyze_pipeline(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    # 1. Create a submission via POST /submissions
    sub_resp = client.post(
        "/submissions",
        json={"code": "API_KEY = 'mysecret'\n\ndef temp():\n    pass", "language": "python"}
    )
    assert sub_resp.status_code == 201
    sub_id = sub_resp.json()["submission_id"]
    
    # 2. Trigger pipeline run via POST /submissions/{id}/analyze
    analysis_resp = client.post(f"/submissions/{sub_id}/analyze")
    assert analysis_resp.status_code == 200
    findings = analysis_resp.json()
    
    # Check findings structure and contents
    assert len(findings) >= 2
    categories = {f["category"] for f in findings}
    assert "hardcoded_secret" in categories
    assert "poor_naming" in categories
    
    # 3. Retrieve findings again via GET /submissions/{id}/findings to confirm DB persistence
    get_resp = client.get(f"/submissions/{sub_id}/findings")
    assert get_resp.status_code == 200
    db_findings = get_resp.json()
    assert len(db_findings) == len(findings)
