"""
orchestrator.py — Pipeline Orchestrator with real-time job status tracking.

Runs the full 4-stage pipeline as a background task:
  Stage 1: analysis + security (concurrent)
  Stage 2: remediation
  Stage 3: summary
  Stage 4: done

Each stage updates the job's stage + per-agent status in the DB so the
/api/jobs/{jobId}/status endpoint can serve live progress.
"""

from __future__ import annotations

import asyncio
import logging
import traceback
from typing import List

from agents.code_analysis_agent import analyze as quality_analyze
from agents.security_agent import analyze as security_analyze
from agents.remediation_agent import remediate
from agents.pr_summary_agent import summarize
from agents.db import get_submission, save_findings, update_job, create_job
from agents.models import Finding

logger = logging.getLogger(__name__)


async def run_pipeline(job_id: str, submission_id: str) -> None:
    """
    Full async pipeline. Designed to be launched as a background task via
    asyncio.create_task() so it doesn't block the HTTP response.
    """
    try:
        res = get_submission(submission_id)
        if not res:
            update_job(job_id, stage="done", error=f"Submission {submission_id} not found")
            return

        code, language, filename = res

        # ------------------------------------------------------------------ #
        # Stage 1: Code Analysis + Security (concurrent)
        # ------------------------------------------------------------------ #
        update_job(
            job_id,
            stage="analysis",
            agent_analysis="running",
            agent_security="running",
        )

        quality_task = asyncio.to_thread(quality_analyze, code, language)
        security_task = asyncio.to_thread(security_analyze, code, language)
        quality_findings, security_findings = await asyncio.gather(quality_task, security_task)

        update_job(job_id, agent_analysis="done", agent_security="done")

        # ------------------------------------------------------------------ #
        # Stage 2: Remediation
        # ------------------------------------------------------------------ #
        update_job(job_id, stage="remediation", agent_remediation="running")

        merged: List[Finding] = quality_findings + security_findings
        merged.sort(key=lambda f: (f.severity, f.line_start))

        # Run remediation in a thread (may call RAG engine)
        merged = await asyncio.to_thread(remediate, merged)

        update_job(job_id, agent_remediation="done")

        # ------------------------------------------------------------------ #
        # Stage 3: PR Summary
        # ------------------------------------------------------------------ #
        update_job(job_id, stage="summary", agent_summary="running")

        summary_result = await asyncio.to_thread(summarize, merged)
        # Store summary in extras of a special sentinel finding (or just in job row)
        # We persist summary JSON in the job error field as a small hack to avoid
        # a new DB table — keyed with prefix "summary:"
        import json
        update_job(
            job_id,
            agent_summary="done",
            error="summary:" + json.dumps(summary_result),  # repurpose error col
        )

        # ------------------------------------------------------------------ #
        # Stage 4: Persist findings + done
        # ------------------------------------------------------------------ #
        save_findings(submission_id, merged)
        update_job(job_id, stage="done")

    except Exception as exc:
        tb = traceback.format_exc()
        logger.error("Pipeline FAILED for job %s: %s\n%s", job_id, exc, tb)
        print(f"[PIPELINE ERROR] job={job_id}: {exc}\n{tb}", flush=True)
        update_job(job_id, stage="done", error=f"Pipeline error: {exc}")


# ---------------------------------------------------------------------------
# Legacy sync entry point (kept for backward compat with tests/scripts)
# ---------------------------------------------------------------------------

async def analyze_submission(submission_id: str) -> List[Finding]:
    """
    Lightweight wrapper that creates a job, runs the pipeline inline,
    and returns the findings list. Used by legacy scripts and tests.
    """
    job_id = create_job(submission_id)
    await run_pipeline(job_id, submission_id)
    from agents.db import get_findings
    rows = get_findings(submission_id)
    # Convert dicts back to Finding objects for legacy callers
    from agents.models import Finding as F, Severity
    import json
    findings = []
    for r in rows:
        findings.append(F(
            type=r["type"],
            severity=Severity(r["severity"]),
            line_start=r["line_start"],
            line_end=r["line_end"],
            title=r["title"],
            description=r["description"],
            category=r["category"],
            source_agent=r["source_agent"],
            extra=json.loads(r["extra"]) if isinstance(r["extra"], str) else r.get("extra", {}),
        ))
    return findings
