"""
tasks/email_consistency.py
============================
V10 Email Architecture — Step 5: Chord Callback

Triggered automatically when all 4 parallel tasks complete.

Reads:   /shared/emails/{email_id}/header_features.json
         /shared/emails/{email_id}/url_features.json
         /shared/emails/{email_id}/attachment_features.json
         /shared/emails/{email_id}/content_features.json
Runs:    Correlates all evidence — matches header/body/URL/attachment consistency
Writes:  /shared/emails/{email_id}/email_consistency.json
"""

import json
import logging
import os

from celery_worker import celery
from config import settings

logger = logging.getLogger(__name__)

SHARED_DIR = getattr(settings, "EMAIL_SHARED_DIR", "/shared/scans")

# Severity rank for aggregation
_SEVERITY_RANK = {"Safe": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_RANK_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}


def _email_dir(email_id: str) -> str:
    return os.path.join(SHARED_DIR, "emails", email_id)


def _load_feature(email_dir: str, filename: str) -> dict:
    """Load a feature JSON file; return empty dict if missing."""
    path = os.path.join(email_dir, filename)
    if not os.path.exists(path):
        logger.warning("Feature file missing: %s", path)
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _overall_severity(scores: list[int]) -> str:
    total = sum(scores)
    if total >= 80:
        return "Critical"
    elif total >= 60:
        return "High"
    elif total >= 40:
        return "Medium"
    elif total >= 20:
        return "Low"
    return "Safe"


@celery.task(
    bind=True,
    name="tasks.email_consistency.email_consistency_task",
    queue="default",
    max_retries=2,
    default_retry_delay=5,
    acks_late=True,
    soft_time_limit=60,
    time_limit=90,
)
def email_consistency_task(self, results, email_id: str):
    """
    Chord callback — fires when all 4 parallel tasks have completed.
    'results' is a list of return values from the parallel tasks (each is email_id).

    Delegates all cross-signal correlation to EmailConsistencyEngine.analyze()
    which applies proper weighted scoring and 7 compound detection rules.
    """
    logger.info("email_consistency_task started email_id=%s", email_id)

    email_dir = _email_dir(email_id)

    # ── Load all 4 feature files ───────────────────────────────────────────
    header  = _load_feature(email_dir, "header_features.json")
    url     = _load_feature(email_dir, "url_features.json")
    attach  = _load_feature(email_dir, "attachment_features.json")
    content = _load_feature(email_dir, "content_features.json")

    # ── Delegate to EmailConsistencyEngine (Audit 2.0 Fix #2) ─────────────
    # EmailConsistencyEngine.analyze() applies:
    #   - Weighted signal scoring: header 30%, url 30%, attachment 25%, content 15%
    #   - 7 compound cross-signal correlation rules
    #   - Confidence calculation based on non-zero signal agreement
    try:
        from consistency_engine.email_consistency_engine import EmailConsistencyEngine
        consistency_report_data = EmailConsistencyEngine.analyze(
            header_features=header,
            url_features=url,
            attachment_features=attach,
            content_features=content,
        )
    except Exception:
        logger.exception(
            "EmailConsistencyEngine.analyze() failed for email_id=%s — "
            "falling back to inline aggregation", email_id
        )
        # ── Fallback: basic inline aggregation (preserved from original) ──
        header_score     = header.get("header_score", 0)
        url_score        = url.get("url_score", 0)
        attachment_score = attach.get("attachment_score", 0)
        content_score    = content.get("content_score", 0)

        all_reasons = []
        for block in [
            header.get("authentication", {}),
            header.get("identity", {}),
            url.get("urls", {}),
            url.get("infrastructure", {}),
            attach.get("attachments", {}),
            content.get("content", {}),
        ]:
            all_reasons.extend(block.get("reasons", []))

        consistency_flags = []
        if url_score >= 50 and attachment_score == 0:
            consistency_flags.append("High URL risk with no attachments — possible phishing link")
        if header_score >= 40 and content_score >= 40:
            consistency_flags.append("Authentication failure combined with urgent content — high phishing confidence")
        if attachment_score >= 60 and header_score < 20:
            consistency_flags.append("Dangerous attachment from seemingly legitimate sender — possible targeted attack")

        overall_score = min(
            int((header_score + url_score + attachment_score + content_score) / 4),
            100,
        )
        overall_severity = _overall_severity([header_score, url_score, attachment_score, content_score])

        consistency_report_data = {
            "overall_score":    overall_score,
            "overall_severity": overall_severity,
            "scores": {
                "header":     header_score,
                "url":        url_score,
                "attachment": attachment_score,
                "content":    content_score,
            },
            "consistency_flags": consistency_flags,
            "all_reasons":       all_reasons,
            "classification": (
                "phishing" if overall_score >= 60
                else "suspicious" if overall_score >= 30
                else "clean"
            ),
        }

    # ── Attach email_id to the report before persisting ───────────────────
    consistency_report_data["email_id"] = email_id

    output_path = os.path.join(email_dir, "email_consistency.json")
    tmp_path    = output_path + ".tmp"
    os.makedirs(email_dir, exist_ok=True)
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(consistency_report_data, f, indent=2)
    os.replace(tmp_path, output_path)  # atomic write

    logger.info(
        "email_consistency_task done email_id=%s overall_score=%s severity=%s classification=%s",
    )
    return email_id
