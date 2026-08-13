"""
app.py — FastAPI application serving the AI Code Review & Security Analysis pipeline.

API Contract
------------
POST   /api/submissions
GET    /api/jobs/{jobId}/status
GET    /api/jobs/{jobId}/findings
POST   /api/jobs/{jobId}/assistant
GET    /api/jobs/{jobId}/report?format=pdf|json
"""

from __future__ import annotations

import asyncio
import json
import logging
import traceback
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, FileResponse
from pydantic import BaseModel, Field
import os
from dotenv import load_dotenv
load_dotenv()

from agents.db import (
    save_submission, get_submission, create_job,
    get_job, get_findings, update_job
)
from agents.orchestrator import run_pipeline
from agents.conversational_assistant import answer as assistant_answer
from agents.pr_summary_agent import compute_health_score, count_by_severity
from agents.report_generator import generate_json_report, generate_pdf_report
from agents.models import Finding, Severity


# ---------------------------------------------------------------------------
# App + CORS
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Code Review & Security Analysis API",
    description="Multi-agent pipeline: code analysis, security scanning, remediation & RAG assistant.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Startup: initialise DB
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    from agents.db import init_db
    init_db()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class SubmissionRequest(BaseModel):
    language: Literal["python", "java"] = Field(..., description="Source language")
    source: Optional[str] = Field(None, description="Source code text")
    code: Optional[str] = Field(None, description="Legacy source code text")
    filename: Optional[str] = Field(None, description="Original filename (optional)")


class SubmissionResponse(BaseModel):
    jobId: str


class LegacySubmissionRequest(BaseModel):
    language: Literal["python", "java"] = Field(..., description="Source language")
    source: Optional[str] = Field(None, description="Source code text")
    code: Optional[str] = Field(None, description="Legacy source code text")
    filename: Optional[str] = Field(None, description="Original filename (optional)")


class AssistantRequest(BaseModel):
    message: str = Field(..., min_length=1)
    history: Optional[list[dict]] = Field(
        default=None,
        description="Optional prior conversation turns for multi-turn context. "
                    "Each entry: {role: 'user'|'assistant', content: str}"
    )
    codeContext: Optional[str] = Field(
        None,
        description="Optional source code snippet for context-aware analysis"
    )


# ---------------------------------------------------------------------------
# Helper: build findings response
# ---------------------------------------------------------------------------

def _build_findings_response(submission_id: str, filename: str) -> dict:
    rows = get_findings(submission_id)

    # Reconstruct Finding objects for score calculation
    finding_objs = []
    for r in rows:
        finding_objs.append(Finding(
            type=r["type"],
            severity=Severity(r["severity"]),
            line_start=r["line_start"],
            line_end=r["line_end"],
            title=r["title"],
            description=r["description"],
            category=r["category"],
            source_agent=r["source_agent"],
            extra={},
        ))

    health_score = compute_health_score(finding_objs)
    counts = count_by_severity(finding_objs)

    findings_out = []
    for r in rows:
        extra = r.get("extra", {})
        if isinstance(extra, str):
            try:
                extra = json.loads(extra)
            except Exception:
                extra = {}
        findings_out.append({
            "id": str(r["id"]),
            "severity": r["severity"],
            "agent": r["source_agent"],
            "title": r["title"],
            "description": r["description"],
            "file": filename,
            "line": r["line_start"],
            "line_end": r["line_end"],
            "category": r["category"],
            "fix": r.get("fix", ""),
        })

    return {
        "healthScore": health_score,
        "counts": counts,
        "findings": findings_out,
    }


# ---------------------------------------------------------------------------
# Helper: resolve job → submission
# ---------------------------------------------------------------------------

def _require_job(job_id: str) -> dict:
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    return job


def _require_submission(submission_id: str) -> tuple:
    sub = get_submission(submission_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Submission not found.")
    return sub   # (code, language, filename)


def _extract_source(req: SubmissionRequest | LegacySubmissionRequest) -> str:
    source = (req.source or req.code or "").strip()
    if not source:
        raise HTTPException(status_code=422, detail="Source code is required.")
    return source


# ---------------------------------------------------------------------------
# POST /api/submissions
# ---------------------------------------------------------------------------

@app.post(
    "/api/submissions",
    response_model=SubmissionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit source code for analysis",
    tags=["Pipeline"],
)
async def submit_code(req: SubmissionRequest, background_tasks: BackgroundTasks):
    """
    Accepts code, stores it, creates a job, kicks off background analysis pipeline.
    Returns { jobId } immediately so the client can poll /status.
    """
    source = _extract_source(req)
    filename = req.filename or ("untitled.py" if req.language == "python" else "untitled.java")

    # Save submission
    submission_id = save_submission(source, req.language, filename)

    # Create job record
    job_id = create_job(submission_id)

    # Launch background pipeline (non-blocking)
    background_tasks.add_task(_run_pipeline_bg, job_id, submission_id)

    return SubmissionResponse(jobId=job_id)


@app.post("/submissions", status_code=status.HTTP_201_CREATED, tags=["Legacy"])
async def submit_legacy_submission(req: LegacySubmissionRequest):
    """Backward-compatible endpoint for older clients that post to /submissions."""
    source = _extract_source(req)

    # ── Syntax validation ──────────────────────────────────────────────────
    if req.language == "python":
        try:
            compile(source, "<string>", "exec")
        except SyntaxError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Syntax validation failed: {e.msg} (line {e.lineno})",
            )
    elif req.language == "java":
        # Basic structural validation: must contain at least one class/interface/enum
        import re as _re
        if not _re.search(r'\b(class|interface|enum)\b', source):
            raise HTTPException(
                status_code=400,
                detail="Syntax validation failed: Java source must contain a class, interface, or enum declaration.",
            )

    filename = req.filename or ("untitled.py" if req.language == "python" else "untitled.java")
    submission_id = save_submission(source, req.language, filename)
    return {"submission_id": submission_id}


@app.post("/submissions/{submission_id}/analyze", tags=["Legacy"])
async def analyze_legacy_submission(submission_id: str):
    """Backward-compatible endpoint that runs the pipeline and returns findings."""
    _require_submission(submission_id)
    job_id = create_job(submission_id)
    await run_pipeline(job_id, submission_id)
    rows = get_findings(submission_id)
    return [
        {
            "id": row["id"],
            "type": row["type"],
            "severity": row["severity"],
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "title": row["title"],
            "description": row["description"],
            "category": row["category"],
            "source_agent": row["source_agent"],
            "fix": row.get("fix", ""),
        }
        for row in rows
    ]


@app.get("/submissions/{submission_id}/findings", tags=["Legacy"])
async def get_legacy_submission_findings(submission_id: str):
    """Backward-compatible endpoint for older clients that fetch findings from /submissions."""
    _require_submission(submission_id)
    return get_findings(submission_id)


async def _run_pipeline_bg(job_id: str, submission_id: str):
    """Thin wrapper so BackgroundTasks can call the async pipeline."""
    try:
        await run_pipeline(job_id, submission_id)
    except Exception as exc:
        tb = traceback.format_exc()
        logging.error("[BG TASK ERROR] job=%s: %s\n%s", job_id, exc, tb)
        print(f"[BG TASK ERROR] job={job_id}: {exc}\n{tb}", flush=True)


# ---------------------------------------------------------------------------
# GET /api/jobs/{jobId}/status
# ---------------------------------------------------------------------------

@app.get(
    "/api/jobs/{jobId}/status",
    summary="Poll pipeline stage & agent status",
    tags=["Pipeline"],
)
async def get_job_status(jobId: str):
    """
    Returns the current pipeline stage and per-agent status.

    Stage:  "analysis" | "security" | "remediation" | "summary" | "done"
    Agents: each "queued" | "running" | "done"
    """
    job = _require_job(jobId)
    return {
        "stage": job["stage"],
        "agents": {
            "analysis": job["agent_analysis"],
            "security": job["agent_security"],
            "remediation": job["agent_remediation"],
            "summary": job["agent_summary"],
        },
        "error": job.get("error") if not (job.get("error") or "").startswith("summary:") else None,
    }


# ---------------------------------------------------------------------------
# GET /api/jobs/{jobId}/findings
# ---------------------------------------------------------------------------

@app.get(
    "/api/jobs/{jobId}/findings",
    summary="Get aggregated findings with health score",
    tags=["Results"],
)
async def get_job_findings(jobId: str):
    """
    Returns the findings dashboard payload:
    { healthScore, counts, findings[] }
    """
    job = _require_job(jobId)
    sub = _require_submission(job["submission_id"])
    code, language, filename = sub

    if job["stage"] != "done" and job["agent_analysis"] == "queued":
        return {
            "healthScore": 100,
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "findings": [],
            "message": "Analysis still in progress.",
        }

    return _build_findings_response(job["submission_id"], filename)


# ---------------------------------------------------------------------------
# POST /api/jobs/{jobId}/assistant
# ---------------------------------------------------------------------------

@app.post(
    "/api/jobs/{jobId}/assistant",
    summary="Ask the conversational code assistant with code context",
    tags=["Assistant"],
)
async def ask_assistant(jobId: str, req: AssistantRequest):
    """
    Queries the RAG-grounded conversational assistant with full code and findings context.
    
    The assistant receives:
    - The user's question/message
    - Conversation history for multi-turn context
    - Source code snippet for code-aware analysis
    - All findings from the analysis
    
    Returns { reply, sources, referencedFindingIds, codeFix }
    """
    job = _require_job(jobId)
    sub = _require_submission(job["submission_id"])
    code, language, filename = sub
    
    # Get findings for context
    findings_rows = get_findings(job["submission_id"])
    
    # Transform findings to include in assistant context
    findings_context = []
    for r in findings_rows:
        findings_context.append({
            "id": str(r["id"]),
            "type": r["type"],
            "severity": r["severity"],
            "line": r["line_start"],
            "line_end": r["line_end"],
            "title": r["title"],
            "description": r["description"],
            "category": r["category"],
            "source_agent": r["source_agent"],
            "fix": r.get("fix", ""),
        })
    
    # Build context message with code and findings
    code_context_msg = (
        f"**Code Context:**\n"
        f"File: {filename}\n"
        f"Language: {language}\n"
        f"Lines: {len(code.splitlines())}\n\n"
        f"**Findings:** {len(findings_context)} issues found\n"
    )
    
    for f in findings_context[:5]:  # Include top 5 findings in context
        code_context_msg += f"- [{f['severity']}] Line {f['line']}: {f['title']}\n"
    
    # Call assistant with enriched context
    result = await asyncio.to_thread(
        assistant_answer, 
        req.message, 
        5, 
        req.history,
        code_context=code,  # Pass full source code
        findings=findings_context,  # Pass all findings
        language=language,
        filename=filename
    )
    
    return result


# ---------------------------------------------------------------------------
# GET /api/jobs/{jobId}/report
# ---------------------------------------------------------------------------

@app.get(
    "/api/jobs/{jobId}/report",
    summary="Download PDF or JSON report",
    tags=["Results"],
)
async def get_report(jobId: str, format: Literal["pdf", "json"] = "json"):
    """
    Generates and serves a downloadable report.
    ?format=pdf  → application/pdf
    ?format=json → application/json (default)
    """
    job = _require_job(jobId)
    sub = _require_submission(job["submission_id"])
    code, language, filename = sub

    # Build summary from job
    summary_data = {}
    error_col = job.get("error") or ""
    if error_col.startswith("summary:"):
        try:
            summary_data = json.loads(error_col[len("summary:"):])
        except Exception:
            pass

    if not summary_data:
        # Regenerate from findings
        from agents.pr_summary_agent import summarize
        from agents.models import Finding as F, Severity
        rows = get_findings(job["submission_id"])
        finding_objs = [
            F(
                type=r["type"], severity=Severity(r["severity"]),
                line_start=r["line_start"], line_end=r["line_end"],
                title=r["title"], description=r["description"],
                category=r["category"], source_agent=r["source_agent"], extra={},
            )
            for r in rows
        ]
        summary_data = summarize(finding_objs)

    submission_info = {"filename": filename, "language": language}
    findings_rows = get_findings(job["submission_id"])

    if format == "pdf":
        pdf_bytes = await asyncio.to_thread(
            generate_pdf_report, jobId, submission_info, summary_data, findings_rows
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="report-{jobId[:8]}.pdf"'},
        )
    else:
        json_bytes = await asyncio.to_thread(
            generate_json_report, jobId, submission_info, summary_data, findings_rows
        )
        return Response(
            content=json_bytes,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="report-{jobId[:8]}.json"'},
        )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Meta"])
async def health():
    return {"status": "ok", "version": "2.0.0"}


# ---------------------------------------------------------------------------
# Legacy endpoints (for backward compat with code.html / old frontend)
# ---------------------------------------------------------------------------

class LegacyAnalyzeRequest(BaseModel):
    code: str
    language: str
    file_name: Optional[str] = "untitled"


@app.post("/api/v1/analyze", tags=["Legacy"])
async def legacy_analyze(req: LegacyAnalyzeRequest, background_tasks: BackgroundTasks):
    """
    Legacy single-call endpoint used by code.html frontend.
    Runs pipeline synchronously and returns findings immediately.
    """
    filename = req.file_name or "untitled"
    submission_id = save_submission(req.code, req.language, filename)
    job_id = create_job(submission_id)

    # Run pipeline inline (blocking) for legacy compat
    await run_pipeline(job_id, submission_id)

    rows = get_findings(submission_id)
    from agents.models import Finding as F, Severity
    finding_objs = [
        F(
            type=r["type"], severity=Severity(r["severity"]),
            line_start=r["line_start"], line_end=r["line_end"],
            title=r["title"], description=r["description"],
            category=r["category"], source_agent=r["source_agent"], extra={},
        )
        for r in rows
    ]

    from agents.pr_summary_agent import compute_health_score
    score = compute_health_score(finding_objs)

    return {
        "submission_id": submission_id,
        "overall_score": score,
        "summary": f"{len(rows)} issue(s) found. Health score: {score}/100.",
        "findings": [
            {
                "id": str(r["id"]),
                "severity": r["severity"],
                "agent_source": r["source_agent"],
                "title": r["title"],
                "description": r["description"],
                "line_start": r["line_start"],
                "line_end": r["line_end"],
                "category": r["category"],
                "code_snippet": "",
                "recommendation": r.get("fix", ""),
                "cwe_id": None,
            }
            for r in rows
        ],
    }


# ---------------------------------------------------------------------------
# Static Files & SPA Root
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def serve_root():
    """Serve index.html at root"""
    return FileResponse(
        os.path.join(os.path.dirname(__file__), "index.html"),
        media_type="text/html",
        headers={"Cache-Control": "no-cache"},
    )
