"""Fail closed when any email chord member or finalizer fails."""
import json
import logging
from pathlib import Path
from celery import Task
from config import settings


class EmailAnalysisTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        email_id = kwargs.get("email_id") or (args[-1] if args else None)
        try:
            from services.email_investigation import _validate_email_id
            from services.diagnostic_reports import save_report
            _validate_email_id(email_id)
            directory = Path(settings.EMAIL_SHARED_DIR) / "emails" / email_id
            owner = json.loads((directory / "owner.json").read_text(encoding="utf-8"))
            report = {"scan_type": "email", "email_id": email_id, "status": "unavailable",
                      "risk_score": None, "severity": "UNKNOWN", "availability": "unavailable",
                      "findings": ["Email analysis did not complete; no clean verdict is available"]}
            if not save_report(owner["scan_id"], report, "email_scan_unavailable", owner_user_id=owner["owner_user_id"]):
                return
            path = directory / "risk_report.json.tmp"
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            path.replace(directory / "risk_report.json")
        except Exception:
            logging.getLogger(__name__).exception("Could not persist failed email analysis")
