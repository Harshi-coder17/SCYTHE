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
from tasks.email_failure import EmailAnalysisTask
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
    base=EmailAnalysisTask,
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
    if not all((header, url, attach, content)):
        raise ValueError("Email evidence is incomplete; no clean result is available")
    from consistency_engine.email_consistency_engine import EmailConsistencyEngine
    consistency_report_data = EmailConsistencyEngine.analyze(
        header_features=header, url_features=url, attachment_features=attach, content_features=content,
    )

    consistency_report_data["email_id"] = email_id

    output_path = os.path.join(email_dir, "email_consistency.json")
    tmp_path    = output_path + ".tmp"
    os.makedirs(email_dir, exist_ok=True)
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(consistency_report_data, f, indent=2)
    os.replace(tmp_path, output_path)  # atomic write

    # Resolve the immutable, operator-bound owner and Scan association.
    owner = _load_feature(email_dir, "owner.json")
    scan_id = owner.get("scan_id")
    if not owner.get("owner_user_id") or not scan_id:
        raise ValueError("Email has no authenticated scan ownership binding")
    from services.diagnostic_reports import save_report
    attachment_unavailable = attach.get("av_available") is False
    final_report = {
        **consistency_report_data,
        "scan_type": "email", "status": "unavailable" if attachment_unavailable else "complete", "email_id": email_id,
        "risk_score": None, "severity": "UNKNOWN", "availability": "evidence_unavailable" if attachment_unavailable else "model_unavailable",
        "attachment_av_available": attach.get("av_available"),
        "heuristic_score": consistency_report_data.get("overall_score"),
        "heuristic_severity": consistency_report_data.get("overall_severity"),
        "findings": consistency_report_data.get("all_reasons", []),
        "feature_availability": {"header": bool(header), "url": bool(url), "attachment": bool(attach), "content": bool(content)},
        "is_placeholder": True, "heuristic_only": True, "automatic_decision": False,
    }
    # Verify scan ownership before publishing any report or broadcasting.
    from database.database import get_db_session
    from database.models import Scan
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == owner["owner_user_id"]).first()
        if scan is None:
            raise ValueError("Email scan owner does not match the collection binding")
    if not save_report(scan_id, final_report, "email_scan_unavailable" if attachment_unavailable else "email_scan_done", owner_user_id=owner["owner_user_id"]):
        return email_id
    report_path = os.path.join(email_dir, "risk_report.json")
    with open(report_path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2)
    os.replace(report_path + ".tmp", report_path)
    logger.info("email_consistency_task done email_id=%s scan_id=%s (heuristic only)", email_id, scan_id)
    return email_id
