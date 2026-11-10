"""Bounded asynchronous v10 upload pipeline. Files are inspected, never executed."""
import hashlib
import io
import json
from pathlib import Path
import zipfile

from celery import Task, chain, chord
from celery_worker import celery
from config import settings
from tasks import validate_scan_id
from services.manual_file_scan_service import _static_analysis, _severity_label, _cache_key, _REDIS, _CACHE_TTL
from services.diagnostic_reports import save_report


class FileAnalysisTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        scan_id = kwargs.get("scan_id") or (args[-1] if args else None)
        try:
            save_report(scan_id, {"scan_type": "file", "status": "unavailable", "risk_score": None,
                                 "severity": "UNKNOWN", "availability": "unavailable",
                                 "findings": ["File analysis did not complete; no clean verdict is available"]}, "file_scan_unavailable")
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Could not persist failed file analysis")


def _inputs(scan_id):
    validate_scan_id(scan_id)
    directory = Path(settings.SHARED_DIR) / "files" / scan_id
    metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    if metadata.get("scan_id") != scan_id:
        raise ValueError("Invalid file ownership association")
    payload = directory / "payload.bin"
    if payload.stat().st_size > 50 * 1024 * 1024:
        raise ValueError("File exceeds bounded analysis limit")
    return directory, metadata, payload


def _save(directory, name, value):
    path = directory / name
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)
    return value


@celery.task(base=FileAnalysisTask, name="tasks.file_analysis.hash", soft_time_limit=30, time_limit=45)
def hash_analysis_task(scan_id):
    directory, metadata, payload = _inputs(scan_id)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    result = {"stage": "hash", "sha256": digest, "integrity": digest == metadata["sha256"]}
    return _save(directory, "hash_features.json", result)


@celery.task(base=FileAnalysisTask, name="tasks.file_analysis.static", soft_time_limit=30, time_limit=45)
def static_analysis_task(scan_id):
    directory, metadata, payload = _inputs(scan_id)
    return _save(directory, "static_features.json", {"stage": "static", **_static_analysis(metadata["filename"], payload.read_bytes())})


@celery.task(base=FileAnalysisTask, name="tasks.file_analysis.malware", soft_time_limit=90, time_limit=120)
def malware_analysis_task(scan_id):
    from services.malware_scanner import scan_file_clamav
    directory, _, payload = _inputs(scan_id)
    try:
        clean, detail = scan_file_clamav(str(payload))
        unavailable = detail.startswith("CRITICAL:") or "scanner unavailable" in detail.lower()
        result = {"stage": "malware", "available": not unavailable, "clean": clean if not unavailable else None,
                  "detail": detail[:500], "malware_detected": clean is False and not unavailable}
    except Exception:
        result = {"stage": "malware", "available": False, "clean": None, "detail": "Anti-malware scanner unavailable", "malware_detected": False}
    return _save(directory, "malware_features.json", result)


@celery.task(base=FileAnalysisTask, name="tasks.file_analysis.content", soft_time_limit=45, time_limit=60)
def content_analysis_task(results, scan_id):
    directory, _, payload = _inputs(scan_id)
    content = payload.read_bytes()
    findings = []
    macro_present = False
    archive_status = "not_applicable"
    if content.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                entries = archive.infolist()
                if len(entries) > 10000 or sum(item.file_size for item in entries) > 100 * 1024 * 1024:
                    archive_status = "unavailable_limit"
                    findings.append("Archive exceeds inspection limits; contents were not expanded")
                else:
                    archive_status = "metadata_inspected"
                    macro_present = any(item.filename.lower().endswith("vbaproject.bin") for item in entries)
                    if macro_present:
                        findings.append("Office archive contains a VBA project")
        except (zipfile.BadZipFile, OSError):
            archive_status = "invalid_archive"
            findings.append("ZIP signature does not match a readable archive")
    # Static PDF flags come from the parallel static stage; no scripts/macros are run.
    evidence = {"stage": "content", "macro_project_present": macro_present, "archive_status": archive_status,
                "findings": findings, "score": 30 if macro_present else 0,
                "execution": "never_executed"}
    _save(directory, "content_features.json", evidence)
    return [*results, evidence]


@celery.task(base=FileAnalysisTask, name="tasks.file_analysis.consistency", soft_time_limit=45, time_limit=60)
def file_consistency_task(results, scan_id):
    directory, metadata, _ = _inputs(scan_id)
    by_stage = {item["stage"]: item for item in results}
    static = by_stage["static"]
    av = by_stage["malware"]
    available = av["available"] and by_stage["hash"]["integrity"]
    findings = static["findings"] + by_stage["content"]["findings"]
    if av["malware_detected"]:
        findings.append(f"ClamAV: {av['detail']}")
    if not by_stage["hash"]["integrity"]:
        findings.append("Payload changed after upload; result unavailable")
    if not av["available"]:
        findings.append("Anti-malware scanner unavailable; file could not be verified")
    score = min(100, static["score"] + by_stage["content"]["score"] + (40 if av["malware_detected"] else 0)) if available else None
    result = {"scan_type": "file", "scan_id": scan_id, "file_id": scan_id, "filename": metadata["filename"],
              "sha256": metadata["sha256"], "size_bytes": metadata["size"], "status": "complete" if available else "unavailable",
              "risk_score": score, "severity": _severity_label(score) if score is not None else "UNKNOWN",
              "findings": findings, "av_detail": av["detail"], "malware_detected": av["malware_detected"],
              "extension": static["extension"], "cached": False, "score_type": "static_heuristic", "pipeline_version": "file_static_v10_v1",
              "availability": "available" if available else "unavailable", "is_placeholder": True,
              "heuristic_only": True, "automatic_decision": False}
    _save(directory, "file_consistency.json", {"integrity": by_stage["hash"]["integrity"], "findings": findings})
    if not save_report(scan_id, result, "file_scan_done" if available else "file_scan_unavailable", owner_user_id=metadata["owner_user_id"]):
        return scan_id
    if available:
        try:
            _REDIS.setex(_cache_key(metadata["sha256"], static["extension"]), _CACHE_TTL, json.dumps(result))
        except Exception:
            pass  # Authoritative report and DB state were already persisted.
    return scan_id


def dispatch_file_analysis(scan_id):
    header = [hash_analysis_task.s(scan_id), static_analysis_task.s(scan_id), malware_analysis_task.s(scan_id)]
    return chord(header)(chain(content_analysis_task.s(scan_id), file_consistency_task.s(scan_id)))
