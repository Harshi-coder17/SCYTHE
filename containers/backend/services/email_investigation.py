"""
services/email_investigation.py
=================================
V10 Email Architecture — Backend Ingestion Service (Step 2).

Called by: api/email_routes.py → POST /api/email/investigate

Responsibilities (per GT Page 10):
  1. Receive prepared email_id from the route handler.
  2. Validate that all required artifact files exist in the shared volume.
  3. Construct the Celery chord of 4 parallel analysis tasks.
  4. Return queued status + job_id immediately.

Chord structure (exactly as specified in GT Page 10):
    chord(
        [
            email_header_analysis_task.s(email_id),
            email_url_analysis_task.s(email_id),
            email_attachment_analysis_task.s(email_id),
            email_content_analysis_task.s(email_id),
        ]
    )(email_consistency_task.s(email_id))

Separating this logic into a dedicated service module (rather than
keeping it inline in the router) follows the same service-layer pattern
used by services/quickscan.py and services/stage2_analysis.py.
"""

import logging
import os
import re

from celery import chord
from fastapi import HTTPException, status

from config import settings

logger = logging.getLogger(__name__)

SHARED_DIR: str = getattr(settings, "EMAIL_SHARED_DIR", "/shared/scans")

# Strict email_id format — guards against path traversal attacks before the id
# is joined into os.path.join(SHARED_DIR, "emails", email_id, ...).
_EMAIL_ID_RE = re.compile(r"^[a-zA-Z0-9_\-.]{1,128}$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _email_dir(email_id: str) -> str:
    return os.path.join(SHARED_DIR, "emails", email_id)


def _validate_email_id(email_id: str) -> None:
    """Raise HTTPException if email_id contains path-traversal characters."""
    if not _EMAIL_ID_RE.match(email_id):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Invalid email_id format — must be 1–128 alphanumeric / "
                "hyphen / underscore / dot characters."
            ),
        )


def _validate_artifacts(email_id: str) -> None:
    """
    Confirm that parsed.json exists in the shared volume for this email_id.
    This is the minimum pre-condition for the analysis chord to run —
    all 4 parallel tasks read parsed.json as their primary input.

    Raises HTTPException(422) if the file is missing.
    """
    parsed_path = os.path.join(_email_dir(email_id), "parsed.json")
    if not os.path.exists(parsed_path):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"parsed.json not found for email_id={email_id!r}. "
                "Ensure the email has been collected and parsed by the "
                "email_engine pipeline before calling this endpoint."
            ),
        )


# ---------------------------------------------------------------------------
# Service function
# ---------------------------------------------------------------------------

def run_email_investigation(email_id: str) -> dict:
    """
    Validate the email_id and dispatch the 4-parallel-task Celery chord.

    Parameters
    ----------
    email_id : Unique identifier for the email whose parsed.json already
               exists on the shared volume.

    Returns
    -------
    {
        "status":   "email_analysis_queued",
        "email_id": <email_id>,
        "job_id":   <celery-chord-uuid>,
    }

    Raises
    ------
    HTTPException(422) — invalid email_id or missing artifact.
    HTTPException(500) — Celery broker unavailable.
    """
    # Step 0: Path-traversal guard
    _validate_email_id(email_id)

    # Step 1: Confirm parsed.json exists
    _validate_artifacts(email_id)

    # Step 2: Import Celery tasks (lazy import to avoid circular imports at
    # module load time and to fail fast if broker is unavailable)
    from tasks.email_header_analysis     import email_header_analysis_task
    from tasks.email_url_analysis        import email_url_analysis_task
    from tasks.email_attachment_analysis import email_attachment_analysis_task
    from tasks.email_content_analysis    import email_content_analysis_task
    from tasks.email_consistency         import email_consistency_task

    # Step 3: Build and dispatch chord
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
            "[email_investigation] Chord queued email_id=%s job_id=%s",
            email_id, job.id,
        )

        # Step 4: Return queued status immediately
        return {
            "status":   "email_analysis_queued",
            "email_id": email_id,
            "job_id":   job.id,
        }

    except Exception:
        logger.exception(
            "[email_investigation] Failed to queue chord for email_id=%s", email_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to queue email investigation. Celery broker may be unavailable.",
        )
