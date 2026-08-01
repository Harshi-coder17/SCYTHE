"""
tasks/email_attachment_analysis.py
====================================
V10 Email Architecture — Child Process P3

Reads:   /shared/emails/{email_id}/parsed.json
Runs:    AttachmentDetector → rule-based attachment signals
         malware_detector   → static AI malware analysis (ai_engine)
Blends both scores → writes to attachment_features.json
Writes:  /shared/emails/{email_id}/attachment_features.json
"""

import json
import logging
import os

from celery_worker import celery
from config import settings

from services.email.detectors.attachment_detector import AttachmentDetector

try:
    from ai_engine import malware_detector as _malware_detector
    _HAS_MALWARE_AI = True
except ImportError:
    _HAS_MALWARE_AI = False

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

    # ── Run AttachmentDetector (rule-based) ───────────────────────────
    attachment_result = AttachmentDetector().detect(email_json)

    # ── Run malware_detector (ai_engine static analysis) ───────────────
    malware_result: dict = {}
    if _HAS_MALWARE_AI:
        malware_result = _malware_detector.analyze(
            attachments_block=email_json.get("attachments", {})
        )

    # ── Blend scores (60% rule-based + 40% AI static if available) ────
    if malware_result:
        blended_score = int(
            attachment_result["score"] * 0.60 + malware_result["score"] * 0.40
        )
        # Escalate malware_detected flag
        malware_detected = (attachment_result.get("score", 0) >= 60
                            or malware_result.get("malware_detected", False))
    else:
        blended_score = attachment_result["score"]
        malware_detected = attachment_result.get("score", 0) >= 60

    blended_score = min(blended_score, 100)

    def _severity(s: int) -> str:
        if s <= 20: return "Safe"
        elif s <= 40: return "Low"
        elif s <= 60: return "Medium"
        elif s <= 80: return "High"
        return "Critical"

    attachment_features = {
        "email_id":         email_id,
        "attachment_score": blended_score,
        "severity":         _severity(blended_score),
        "malware_detected": malware_detected,
        "attachment_count": email_json.get("attachments", {}).get("attachment_count", 0),
        "attachments":      attachment_result,
        "malware_ai":       malware_result,
        "raw_attachments":  email_json.get("attachments", {}).get("attachments", []),
    }

    output_path = os.path.join(email_dir, "attachment_features.json")
    tmp_path = output_path + ".tmp"
    os.makedirs(email_dir, exist_ok=True)
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(attachment_features, f, indent=2)
    os.replace(tmp_path, output_path)  # atomic — prevents partial-read by email_consistency_task

    logger.info(
        "email_attachment_analysis done email_id=%s blended_score=%s severity=%s malware=%s",
        email_id, blended_score, attachment_features["severity"], malware_detected,
    )
    return email_id
