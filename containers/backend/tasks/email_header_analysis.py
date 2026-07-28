"""
tasks/email_header_analysis.py
==============================
V10 Email Architecture — Child Process P1

Reads:   /shared/emails/{email_id}/parsed.json
Runs:    AuthenticationDetector  → SPF / DKIM / DMARC / Alignment
         IdentityDetector        → Reply-To mismatch, display name spoof,
                                   typosquatting, homoglyph
Writes:  /shared/emails/{email_id}/header_features.json
"""

import json
import logging
import os

from celery_worker import celery
from config import settings

from services.email.detectors.authentication_detector import AuthenticationDetector
from services.email.detectors.identity_detector import IdentityDetector

logger = logging.getLogger(__name__)

SHARED_DIR = getattr(settings, "EMAIL_SHARED_DIR", "/shared/scans")


def _email_dir(email_id: str) -> str:
    return os.path.join(SHARED_DIR, "emails", email_id)


@celery.task(
    bind=True,
    name="tasks.email_header_analysis.email_header_analysis_task",
    queue="default",
    max_retries=3,
    default_retry_delay=5,
    acks_late=True,
    soft_time_limit=120,
    time_limit=150,
)
def email_header_analysis_task(self, email_id: str):
    logger.info("email_header_analysis started email_id=%s", email_id)

    email_dir = _email_dir(email_id)
    parsed_path = os.path.join(email_dir, "parsed.json")

    if not os.path.exists(parsed_path):
        raise FileNotFoundError(
            f"parsed.json not found for email_id={email_id} at {parsed_path}"
        )

    with open(parsed_path, "r", encoding="utf-8") as f:
        email_json = json.load(f)

    # ── Run detectors ──────────────────────────────────────────────────────
    auth_result = AuthenticationDetector().detect(email_json)
    identity_result = IdentityDetector().detect(email_json)

    # ── Combine into header_features ───────────────────────────────────────
    header_score = min(auth_result["score"] + identity_result["score"], 100)
    header_features = {
        "email_id": email_id,
        "header_score": header_score,
        "severity": auth_result["severity"] if auth_result["score"] >= identity_result["score"] else identity_result["severity"],
        "authentication": auth_result,
        "identity": identity_result,
        "received_chain": email_json.get("received_chain", {}),
    }

    output_path = os.path.join(email_dir, "header_features.json")
    tmp_path = output_path + ".tmp"
    os.makedirs(email_dir, exist_ok=True)
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(header_features, f, indent=2)
    os.replace(tmp_path, output_path)  # atomic — prevents partial-read by email_consistency_task

    logger.info(
        "email_header_analysis done email_id=%s score=%s severity=%s",
        email_id, header_score, header_features["severity"],
    )
    return email_id
