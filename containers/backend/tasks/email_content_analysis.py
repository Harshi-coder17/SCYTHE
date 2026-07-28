"""
tasks/email_content_analysis.py
=================================
V10 Email Architecture — Child Process P4

Reads:   /shared/emails/{email_id}/parsed.json
Runs:    ContentDetector → credential theft, financial scams, urgency,
                           spam score, HTML obfuscation, hidden text,
                           login forms, JavaScript, external resources,
                           suspicious keywords
Writes:  /shared/emails/{email_id}/content_features.json

Note: No phishing_nlp.py exists in ai_engine/ — ContentDetector is used directly.
"""

import json
import logging
import os

from celery_worker import celery
from config import settings

from services.email.detectors.content_detector import ContentDetector

logger = logging.getLogger(__name__)

SHARED_DIR = getattr(settings, "EMAIL_SHARED_DIR", "/shared/scans")


def _email_dir(email_id: str) -> str:
    return os.path.join(SHARED_DIR, "emails", email_id)


@celery.task(
    bind=True,
    name="tasks.email_content_analysis.email_content_analysis_task",
    queue="default",
    max_retries=3,
    default_retry_delay=5,
    acks_late=True,
    soft_time_limit=120,
    time_limit=150,
)
def email_content_analysis_task(self, email_id: str):
    logger.info("email_content_analysis started email_id=%s", email_id)

    email_dir = _email_dir(email_id)
    parsed_path = os.path.join(email_dir, "parsed.json")

    if not os.path.exists(parsed_path):
        raise FileNotFoundError(
            f"parsed.json not found for email_id={email_id} at {parsed_path}"
        )

    with open(parsed_path, "r", encoding="utf-8") as f:
        email_json = json.load(f)

    # ── Run detector ───────────────────────────────────────────────────────
    content_result = ContentDetector().detect(email_json)

    content_features = {
        "email_id": email_id,
        "content_score": content_result["score"],
        "severity": content_result["severity"],
        "content": content_result,
        "subject": email_json.get("metadata", {}).get("subject", ""),
        "language": email_json.get("content", {}).get("language", None),
    }

    output_path = os.path.join(email_dir, "content_features.json")
    tmp_path = output_path + ".tmp"
    os.makedirs(email_dir, exist_ok=True)
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(content_features, f, indent=2)
    os.replace(tmp_path, output_path)  # atomic — prevents partial-read by email_consistency_task

    logger.info(
        "email_content_analysis done email_id=%s score=%s severity=%s",
        email_id, content_result["score"], content_result["severity"],
    )
    return email_id
