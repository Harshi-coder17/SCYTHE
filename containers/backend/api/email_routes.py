"""
api/email_routes.py
====================
V10 Email Architecture — Backend Ingestion (Step 2)

Mounts at:  /api/email
Endpoint:   POST /api/email/investigate

Receives a parsed email_id, validates the parsed.json exists,
creates a Celery chord of 4 parallel tasks, and returns immediately
with a queued status — exactly as shown in V10 page 10.

Chord structure (from V10 diagram):
    chord(
        [
            email_header_analysis_task.s(email_id),
            email_url_analysis_task.s(email_id),
            email_attachment_analysis_task.s(email_id),
            email_content_analysis_task.s(email_id),
        ]
    )(email_consistency_task.s(email_id))
"""

import logging
import os
import re

from celery import chord
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from config import settings
from database.database import get_db
from database.models import User

logger = logging.getLogger(__name__)

email_router = APIRouter(prefix="/api/email", tags=["email"])

SHARED_DIR = getattr(settings, "EMAIL_SHARED_DIR", "/shared/scans")


# ── Request schema ─────────────────────────────────────────────────────────────

class EmailInvestigateRequest(BaseModel):
    email_id: str


# Strict email_id format: alphanumeric, hyphens, underscores, dots — max 128 chars
# Guards against path-traversal (e.g. "../../etc/passwd") before the id is joined
# into os.path.join(SHARED_DIR, "emails", email_id).
_EMAIL_ID_RE = re.compile(r"^[a-zA-Z0-9_\-.]{1,128}$")


def _validate_email_id(email_id: str) -> None:
    if not _EMAIL_ID_RE.match(email_id):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid email_id format — must be 1–128 alphanumeric/hyphen/underscore/dot characters.",
        )


# ── Endpoint ───────────────────────────────────────────────────────────────────

@email_router.post("/investigate")
def email_investigate(
    payload: EmailInvestigateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    POST /api/email/investigate

    Validates that parsed.json exists for the given email_id, then
    dispatches 4 parallel Celery analysis tasks as a chord with the
    consistency task as the callback.

    Returns:
        {
            "status": "email_analysis_queued",
            "email_id": "<email_id>",
            "job_id": "<celery-chord-id>"
        }
    """
    from tasks.email_header_analysis import email_header_analysis_task
    from tasks.email_url_analysis import email_url_analysis_task
    from tasks.email_attachment_analysis import email_attachment_analysis_task
    from tasks.email_content_analysis import email_content_analysis_task
    from tasks.email_consistency import email_consistency_task

    email_id = payload.email_id

    # ── Step 0: Validate email_id format (path-traversal guard) ──────────
    _validate_email_id(email_id)

    # ── Step 1: Validate parsed.json exists ───────────────────────────────
    parsed_path = os.path.join(SHARED_DIR, "emails", email_id, "parsed.json")
    if not os.path.exists(parsed_path):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"parsed.json not found for email_id={email_id}. "
                "Ensure the email has been collected and parsed before calling this endpoint."
            ),
        )

    # ── Step 2: Build Celery chord ────────────────────────────────────────
    try:
        parallel_tasks = [
            email_header_analysis_task.s(email_id),
            email_url_analysis_task.s(email_id),
            email_attachment_analysis_task.s(email_id),
            email_content_analysis_task.s(email_id),
        ]
        callback = email_consistency_task.s(email_id)
        job = chord(parallel_tasks)(callback)

        logger.info(
            "Email analysis chord queued email_id=%s job_id=%s",
            email_id, job.id,
        )

        return {
            "status": "email_analysis_queued",
            "email_id": email_id,
            "job_id": job.id,
        }

    except Exception:
        logger.exception("Failed to queue email investigation for email_id=%s", email_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to queue email investigation.",
        )
