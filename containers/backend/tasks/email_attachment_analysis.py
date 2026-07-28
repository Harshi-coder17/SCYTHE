"""
tasks/email_attachment_analysis.py
====================================
V10 Email Architecture — Child Process P3

Reads:   /shared/emails/{email_id}/parsed.json
Runs:    AttachmentDetector → malware flag, office macros, password-protected
                              archives, dangerous/double extensions,
                              executables, suspicious MIME types
Writes:  /shared/emails/{email_id}/attachment_features.json
"""

import json
import logging
import os

from celery_worker import celery
from config import settings

from services.email.detectors.attachment_detector import AttachmentDetector

logger = logging.getLogger(__name__)

SHARED_DIR = getattr(settings, "EMAIL_SHARED_DIR", "/shared/scans")


def _email_dir(email_id: str) -> str:
    return os.path.join(SHARED_DIR, "emails", email_id)


@celery.task(
    bind=True,
    name="tasks.email_attachment_analysis.email_attachment_analysis_task",
    queue="default",
    max_retries=3,
    default_retry_delay=5,
    acks_late=True,
    soft_time_limit=120,
    time_limit=150,
)
def email_attachment_analysis_task(self, email_id: str):
    logger.info("email_attachment_analysis started email_id=%s", email_id)

    email_dir = _email_dir(email_id)
    parsed_path = os.path.join(email_dir, "parsed.json")

    if not os.path.exists(parsed_path):
        raise FileNotFoundError(
            f"parsed.json not found for email_id={email_id} at {parsed_path}"
        )

    with open(parsed_path, "r", encoding="utf-8") as f:
        email_json = json.load(f)

    # ── Run detector ───────────────────────────────────────────────────────
    attachment_result = AttachmentDetector().detect(email_json)

    attachment_features = {
        "email_id": email_id,
        "attachment_score": attachment_result["score"],
        "severity": attachment_result["severity"],
        "attachment_count": email_json.get("attachments", {}).get("attachment_count", 0),
        "attachments": attachment_result,
        "raw_attachments": email_json.get("attachments", {}).get("attachments", []),
    }

    output_path = os.path.join(email_dir, "attachment_features.json")
    tmp_path = output_path + ".tmp"
    os.makedirs(email_dir, exist_ok=True)
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(attachment_features, f, indent=2)
    os.replace(tmp_path, output_path)  # atomic — prevents partial-read by email_consistency_task

    logger.info(
        "email_attachment_analysis done email_id=%s score=%s severity=%s",
        email_id, attachment_result["score"], attachment_result["severity"],
    )
    return email_id
