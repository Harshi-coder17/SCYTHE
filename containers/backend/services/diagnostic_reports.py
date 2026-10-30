"""Persist non-deployable file/email diagnostic reports without activating alerts."""
import json
import logging
import os
from pathlib import Path

import redis
from config import settings
from database.database import get_db_session
from database.models import Scan
from tasks import validate_scan_id
from websocket.websocket_manager import websocket_manager

logger = logging.getLogger(__name__)


_TERMINAL = {"failed_timeout", "cancelled", "file_scan_done", "file_scan_unavailable",
             "email_scan_done", "email_scan_unavailable", "file_dispatch_failed", "email_dispatch_failed"}


def write_report_artifact(scan_id: str, report: dict) -> None:
    """Caller must hold the owned Scan row lock before changing canonical output."""
    validate_scan_id(scan_id)
    report.update(scan_id=scan_id, is_placeholder=True, heuristic_only=True, automatic_decision=False)
    directory = Path(settings.SHARED_DIR) / scan_id
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / "risk_report.json.tmp"
    temporary.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    os.replace(temporary, directory / "risk_report.json")


def publish_report(scan_id: str, report: dict, user_id: str) -> None:
    try:
        redis.from_url(settings.REDIS_URL).setex(f"risk:{scan_id}", 3600, json.dumps(report, default=str))
        websocket_manager.broadcast_risk_update_sync(scan_id, report, user_id=user_id)
    except Exception:
        logger.exception("Diagnostic report persisted; cache or websocket update unavailable for %s", scan_id)


def save_report(scan_id: str, report: dict, status: str, owner_user_id: str | None = None) -> bool:
    validate_scan_id(scan_id)
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).with_for_update().first()
        if scan is None or (owner_user_id is not None and scan.user_id != owner_user_id):
            raise ValueError("Owned scan record is missing or does not match")
        path = Path(settings.SHARED_DIR) / scan_id / "risk_report.json"
        if scan.status in _TERMINAL and (scan.status != status or path.exists()):
            logger.info("Ignoring late diagnostic task for terminal scan %s (%s)", scan_id, scan.status)
            return False
        write_report_artifact(scan_id, report)
        scan.status = status
        scan.risk_score = report.get("risk_score")
        scan.severity = report.get("severity")
        user_id = scan.user_id
        db.commit()
    publish_report(scan_id, report, user_id)
    return True
