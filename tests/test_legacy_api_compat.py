from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from app import app
from agents.db import DB_FILE

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_db():
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


def test_legacy_submission_and_analyze_routes(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    response = client.post(
        "/submissions",
        json={"code": "API_KEY = 'super-secret-key'\n", "language": "python"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert "submission_id" in payload

    submission_id = payload["submission_id"]
    analyze_response = client.post(f"/submissions/{submission_id}/analyze")
    assert analyze_response.status_code == 200

    findings = analyze_response.json()
    assert isinstance(findings, list)
    assert findings

    findings_response = client.get(f"/submissions/{submission_id}/findings")
    assert findings_response.status_code == 200
    assert isinstance(findings_response.json(), list)
