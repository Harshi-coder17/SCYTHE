"""Incident-aware retention: an unavailable database never authorizes deletion."""
import json
import logging
import os
from pathlib import Path
import shutil
import stat
import time
from datetime import datetime, timezone

from sqlalchemy import func
from celery_worker import celery
from config import settings
from database.database import SessionLocal
from database.models import Incident, Scan, Statistics
from tasks import _UUID_RE

logger = logging.getLogger(__name__)
_TERMINAL = {"completed", "complete", "failed", "error", "cancelled", "expired",
             "risk_fusion_done", "file_scan_done", "file_scan_failed", "file_scan_unavailable",
             "file_dispatch_failed", "email_scan_done", "email_dispatch_failed",
             "email_risk_fusion_done", "email_investigation_done", "email_investigation_failed",
             "email_scan_unavailable", "blocked_by_cyberintel", "failed_timeout"}


def _timestamp(value):
    if value is None:
        return 0.0
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


def _association(directory):
    ids = set()
    for name in ("owner.json", "metadata.json", "risk_report.json", "email_report.json"):
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            values = [data.get("scan_id"), *(data.get("scan_ids") or [])]
            ids.update(value for value in values if isinstance(value, str) and _UUID_RE.fullmatch(value))
        except (OSError, ValueError, TypeError):
            continue
    return ids


def _remove(directory, root):
    info = directory.lstat()
    if directory.is_symlink() or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024):
        raise OSError("Refusing to remove a link or reparse point")
    resolved = directory.resolve(strict=True)
    if resolved == root or root not in resolved.parents:
        raise OSError("Artifact path is outside the shared directory")
    shutil.rmtree(resolved)


@celery.task(bind=True, name="tasks.file_cleanup", queue="default", max_retries=1, acks_late=True)
def file_cleanup_task(self, retention_days=14, incident_retention_days=None):
    incident_retention_days = incident_retention_days or settings.INCIDENT_RETENTION_DAYS
    if retention_days < 1 or incident_retention_days < retention_days:
        raise ValueError("Retention periods must be positive; incident retention cannot be shorter")
    root = Path(settings.SHARED_DIR).resolve()
    now = time.time()
    cutoff = now - retention_days * 86400
    incident_cutoff = now - incident_retention_days * 86400
    result = dict(status="ok", shared_dir=str(root), retention_days=retention_days,
                  incident_retention_days=incident_retention_days, dirs_removed=0,
                  dirs_skipped=0, orphans_removed=0, db_records_removed=0, errors=0,
                  unknown_associations_retained=0)
    try:
        with os.scandir(root) as entries:
            children = list(entries)
    except OSError:
        return {**result, "status": "error", "detail": "Cannot scan shared_dir", "errors": 1}
    try:
        with SessionLocal() as db:
            rows = {row.id: row for row in db.query(Scan).all()}
            old = db.query(Scan).filter(Scan.created_at <= datetime.fromtimestamp(cutoff, timezone.utc))
            locked = {row.id for row in old.populate_existing().with_for_update(skip_locked=True).all()}
            latest_incident = dict(db.query(Incident.scan_id, func.max(Incident.created_at)).group_by(Incident.scan_id).all())
            eligible = set()
            for scan_id, row in rows.items():
                observed = max(_timestamp(row.created_at), _timestamp(row.updated_at),
                               _timestamp(latest_incident.get(scan_id)))
                limit = incident_cutoff if scan_id in latest_incident else cutoff
                if scan_id in locked and row.status in _TERMINAL and observed <= limit:
                    eligible.add(scan_id)
            protected = set(rows) - eligible
            recent_artifacts = set()

            def sweep(directory, associations, *, uncertain=False):
                try:
                    if directory.is_symlink() or not directory.is_dir():
                        return
                    stamp = directory.stat().st_mtime
                    if associations & protected:
                        result["dirs_skipped"] += 1
                        return
                    if stamp > (incident_cutoff if uncertain else cutoff):
                        result["dirs_skipped"] += 1
                        recent_artifacts.update(associations)
                        if uncertain:
                            result["unknown_associations_retained"] += 1
                        return
                    _remove(directory, root)
                    result["dirs_removed"] += 1
                except OSError:
                    result["errors"] += 1
                    recent_artifacts.update(associations)
                    logger.warning("Artifact removal failed for %s", directory, exc_info=True)

            for child in children:
                directory = Path(child.path)
                if child.is_dir(follow_symlinks=False) and _UUID_RE.fullmatch(child.name):
                    sweep(directory, {child.name})
                elif child.is_dir(follow_symlinks=False) and child.name in {"files", "emails"}:
                    for nested in directory.iterdir():
                        if nested.is_symlink() or not nested.is_dir():
                            continue
                        if not nested.name or len(nested.name) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in nested.name):
                            continue
                        ids = _association(nested)
                        if nested.name in rows:
                            ids.add(nested.name)
                        sweep(nested, ids, uncertain=not ids or bool(ids - set(rows)))
                elif child.is_file(follow_symlinks=False) and child.name.startswith("scan_") and child.name.endswith((".json", ".png")):
                    candidate = child.name[5:41]
                    if candidate in protected or child.stat().st_mtime > cutoff:
                        continue
                    directory.unlink()
                    result["orphans_removed"] += 1
            quarantine = root / "quarantine"
            if quarantine.is_dir() and not quarantine.is_symlink():
                for sample in quarantine.iterdir():
                    if sample.is_file() and not sample.is_symlink() and sample.stat().st_mtime <= incident_cutoff:
                        sample.unlink()
                        result["orphans_removed"] += 1
            if not result["errors"]:
                purge = eligible - recent_artifacts
                for scan_id in purge:
                    db.delete(rows[scan_id])
                db.flush()
                result["db_records_removed"] = len(purge)
                stats = db.query(Statistics).filter(Statistics.id == 1).first()
                if stats is None:
                    stats = Statistics(id=1)
                    db.add(stats)
                stats.total_incidents = db.query(func.count(Incident.id)).scalar() or 0
                stats.critical_count = db.query(func.count(Incident.id)).filter(Incident.severity == "CRITICAL").scalar() or 0
                stats.high_count = db.query(func.count(Incident.id)).filter(Incident.severity == "HIGH").scalar() or 0
                stats.updated_at = func.now()
                db.commit()
            else:
                db.rollback()
                result["status"] = "partial"
    except Exception:
        logger.exception("Retention stopped; database/evidence ownership could not be verified")
        result.update(status="error", errors=result["errors"] + 1,
                      detail="Retention requires verified database ownership and incident state")
    return result
