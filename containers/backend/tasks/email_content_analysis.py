"""
tasks/email_content_analysis.py
=================================
V10 Email Architecture — Child Process P4

Reads:   /shared/emails/{email_id}/parsed.json
Runs:    ContentDetector   → rule-based content signals
         phishing_nlp      → NLP phishing detection (ai_engine)
Blends both scores → writes to content_features.json
Writes:  /shared/emails/{email_id}/content_features.json
"""

import json
import logging
import os

from celery_worker import celery
from config import settings

from services.email.detectors.content_detector import ContentDetector

try:
    from ai_engine import phishing_nlp as _phishing_nlp
    _HAS_NLP = True
except ImportError:
    _HAS_NLP = False

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

    # ── Run ContentDetector (rule-based) ───────────────────────────────
    content_result = ContentDetector().detect(email_json)

    # ── Run phishing_nlp (ai_engine) ────────────────────────────────
    nlp_result: dict = {}
    if _HAS_NLP:
        subject  = email_json.get("metadata", {}).get("subject", "")
        body_raw = email_json.get("content", {}).get("body", "")
        body     = body_raw if isinstance(body_raw, str) else ""
        nlp_result = _phishing_nlp.analyze(
            subject=subject,
            body=body,
            metadata=email_json.get("metadata", {}),
        )

    # ── Blend scores (60% rule-based + 40% NLP if available) ────────────
    if nlp_result:
        blended_score = int(
            content_result["score"] * 0.60 + nlp_result["score"] * 0.40
        )
    else:
        blended_score = content_result["score"]

    blended_score = min(blended_score, 100)

    def _severity(s: int) -> str:
        if s <= 20: return "Safe"
        elif s <= 40: return "Low"
        elif s <= 60: return "Medium"
        elif s <= 80: return "High"
        return "Critical"

    content_features = {
        "email_id":      email_id,
        "content_score": blended_score,
        "severity":      _severity(blended_score),
        "content":       content_result,
        "nlp":           nlp_result,
        "subject":       email_json.get("metadata", {}).get("subject", ""),
        "language":      email_json.get("content", {}).get("language", None),
    }

    output_path = os.path.join(email_dir, "content_features.json")
    tmp_path = output_path + ".tmp"
    os.makedirs(email_dir, exist_ok=True)
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(content_features, f, indent=2)
    os.replace(tmp_path, output_path)  # atomic — prevents partial-read by email_consistency_task

    logger.info(
        "email_content_analysis done email_id=%s blended_score=%s severity=%s",
        email_id, blended_score, content_features["severity"],
    )
    return email_id
