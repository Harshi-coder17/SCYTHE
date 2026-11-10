"""Owned file upload dispatch plus synchronous compatibility analysis.

The API uses queue_manual_file_scan: parallel hash/static/AV tasks, bounded
content inspection, then consistency and persisted diagnostic reports. The
synchronous helper remains available for callers/tests and preserves the
extension-sensitive v2 technical cache and strict AV-unavailable behavior.
"""

import hashlib
import json
import logging
import os
import re
import uuid

import redis
from fastapi import HTTPException, status

from config import settings
from database.models import Scan

logger = logging.getLogger(__name__)

_SHARED_DIR: str = settings.SHARED_DIR
_REDIS: redis.Redis = redis.from_url(settings.REDIS_URL)
_CACHE_TTL: int = 3600  # 1 hour

# Maximum uploaded file size (50 MB)
_MAX_FILE_BYTES: int = 50 * 1024 * 1024

# Dangerous extensions for static classification
_DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".com", ".bat", ".cmd", ".msi", ".msp", ".dll", ".scr",
    ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1",
    ".hta", ".cpl", ".sys", ".jar", ".lnk", ".inf", ".reg",
})

# Macro-capable Office extensions
_MACRO_EXTENSIONS: frozenset[str] = frozenset({
    ".doc", ".dot", ".docm", ".dotm",
    ".xls", ".xlsm", ".xltm", ".xlam",
    ".ppt", ".pptm", ".potm", ".ppam",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_file(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _file_dir(file_id: str) -> str:
    return os.path.join(_SHARED_DIR, "files", file_id)


def _sanitise_filename(filename: str) -> str:
    """Strip path traversal characters from filename."""
    safe = re.sub(r'[\\/:*?"<>|\x00]', "_", filename).strip("._")
    return safe[:200] if safe else "uploaded_file"


def _get_extension(filename: str) -> str:
    _, ext = os.path.splitext(filename.lower())
    return ext


def _static_analysis(filename: str, content: bytes) -> dict:
    """
    Lightweight inline static analysis:
      - Extension classification
      - Magic byte check for executables (MZ, ELF, etc.)
      - Office macro detection (OLE header)
      - PDF JS / action detection
    Returns a risk dict.
    """
    ext = _get_extension(filename)
    score = 0
    findings: list[str] = []

    # ── Extension checks ────────────────────────────────────────────────────
    if ext in _DANGEROUS_EXTENSIONS:
        score += 60
        findings.append(f"Dangerous file extension: {ext}")

    if ext in _MACRO_EXTENSIONS:
        score += 20
        findings.append(f"Macro-capable Office format: {ext}")

    # ── Magic byte checks ────────────────────────────────────────────────────
    header = content[:16] if len(content) >= 16 else content

    # MZ header → Windows PE executable
    if header[:2] == b"MZ":
        score += 50
        findings.append("Windows PE executable (MZ header)")

    # ELF header → Linux executable
    if header[:4] == b"\x7fELF":
        score += 50
        findings.append("ELF binary (Linux executable)")

    # OLE header → Office with potential macros (D0 CF 11 E0)
    if header[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        score += 30
        findings.append("OLE2 compound file (Office document with potential macros)")

    # PDF check — look for /JS or /AA (auto-action) streams
    if content[:5] == b"%PDF-":
        pdf_sample = content[:min(65536, len(content))]
        if b"/JS " in pdf_sample or b"/JavaScript" in pdf_sample:
            score += 35
            findings.append("PDF contains JavaScript stream")
        if b"/AA " in pdf_sample or b"/OpenAction" in pdf_sample:
            score += 25
            findings.append("PDF has auto-action or open-action trigger")

    # ZIP-based check (Office Open XML: .docx, .xlsx, .pptx)
    if header[:4] == b"PK\x03\x04":
        if ext in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}:
            # Treat as Office Open XML; macro check requires content scan
            pass  # benign without macro scan — handled by macro_analysis_task later

    score = min(score, 100)

    def _severity(s: int) -> str:
        if s <= 20:
            return "Safe"
        elif s <= 40:
            return "Low"
        elif s <= 60:
            return "Medium"
        elif s <= 80:
            return "High"
        return "Critical"

    return {
        "score":    score,
        "severity": _severity(score),
        "findings": findings,
        "extension": ext,
    }


def _severity_label(score: float) -> str:
    if score <= 20:
        return "Safe"
    elif score <= 40:
        return "Low"
    elif score <= 60:
        return "Medium"
    elif score <= 80:
        return "High"
    return "Critical"


def _cache_key(file_hash: str, extension: str) -> str:
    # The static score depends on both bytes and extension. The new namespace
    # also invalidates legacy verdicts created before strict AV error handling.
    return f"filescan:v2:{file_hash}:{extension or '<none>'}"


# ---------------------------------------------------------------------------
# Main service function
# ---------------------------------------------------------------------------

def run_manual_file_scan(
    filename: str,
    content: bytes,
    user=None,
    db=None,
) -> dict:
    """
    Perform a full static analysis of an uploaded file.

    Parameters
    ----------
    filename : Original filename as uploaded by the user.
    content  : Raw file bytes.
    user     : Authenticated user ORM object.
    db       : SQLAlchemy database session.

    Returns
    -------
    Full scan result dict suitable for dashboard display.
    """
    # ── Input validation ────────────────────────────────────────────────────
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )
    if len(content) > _MAX_FILE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large: {len(content)} bytes (maximum {_MAX_FILE_BYTES} bytes).",
        )

    safe_name = _sanitise_filename(filename)
    file_hash = _sha256_file(content)
    cache_key = _cache_key(file_hash, _get_extension(safe_name))

    # ── Redis cache check ────────────────────────────────────────────────────
    cached_raw = _REDIS.get(cache_key)
    if cached_raw:
        cached = json.loads(cached_raw)
        # The cache contains only reusable technical findings. Never return
        # the previous caller's scan/file IDs or filename to this caller.
        cached_file_id = str(uuid.uuid4())
        cached["file_id"] = cached_file_id
        cached["filename"] = safe_name
        cached["scan_id"] = cached_file_id
        cached["cached"] = True
        if db is not None and user is not None:
            try:
                scan = Scan(
                    id=cached_file_id,
                    user_id=user.id,
                    url=None,
                    status="file_scan_done",
                    risk_score=cached.get("risk_score"),
                    severity=cached.get("severity") if cached.get("severity") != "Safe" else None,
                )
                db.add(scan)
                db.commit()
                db.refresh(scan)
                cached["scan_id"] = scan.id
            except Exception:
                logger.exception("[manual_file_scan] Cached result persistence failed")
        logger.info(
            "[manual_file_scan] Cache hit hash=%s filename=%r", file_hash[:16], safe_name
        )
        _persist_local_report(cached)
        return cached

    # ── Generate file_id and save artifacts ──────────────────────────────────
    file_id = str(uuid.uuid4())
    file_dir = _file_dir(file_id)
    os.makedirs(file_dir, exist_ok=True)

    # Never use a user-controlled name for the payload: metadata.json is a
    # reserved sidecar name and must not replace bytes before AV scanning.
    payload_name = "payload.bin"
    dest_path = os.path.join(file_dir, payload_name)
    with open(dest_path, "wb") as f:
        f.write(content)

    # Save metadata.json alongside
    metadata = {
        "file_id":   file_id,
        "scan_id":   file_id,
        "filename":  safe_name,
        "sha256":    file_hash,
        "size":      len(content),
        "path":      dest_path,
    }
    with open(os.path.join(file_dir, "metadata.json"), "w", encoding="utf-8") as mf:
        json.dump(metadata, mf, indent=2)

    # ── Static analysis ──────────────────────────────────────────────────────
    static_result = _static_analysis(safe_name, content)
    risk_score = float(static_result["score"])
    severity   = static_result["severity"]

    # ── ClamAV scan — unverified files return unavailable ───────────────────
    malware_detected = False
    av_detail = "Not scanned"
    try:
        from services.malware_scanner import scan_file_clamav
        is_clean, av_detail = scan_file_clamav(dest_path)
        if av_detail.startswith("CRITICAL:") or "scanner unavailable" in av_detail.lower():
            raise HTTPException(status_code=503, detail="Anti-malware scanner unavailable; the file could not be verified.")
        if is_clean is False:
            malware_detected = True
            risk_score = min(risk_score + 40, 100)
            static_result["findings"].append(f"ClamAV: {av_detail}")
            severity = _severity_label(risk_score)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("[manual_file_scan] ClamAV unavailable: %s", exc)
        raise HTTPException(status_code=503, detail="Anti-malware scanner unavailable; the file could not be verified.") from exc

    # ── Persist to Postgres ──────────────────────────────────────────────────
    if db is not None and user is not None:
        try:
            scan = Scan(
                id=file_id,
                user_id=user.id,
                url=None,
                status="file_scan_done",
                risk_score=risk_score,
                severity=severity if severity != "Safe" else None,
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            scan_id = scan.id
        except Exception:
            logger.exception("[manual_file_scan] DB persist failed")
            scan_id = file_id
    else:
        scan_id = file_id

    # ── Build result ─────────────────────────────────────────────────────────
    result = {
        "scan_type":        "file",
        "status":           "complete",
        "file_id":          file_id,
        "scan_id":          scan_id,
        "filename":         safe_name,
        "sha256":           file_hash,
        "size_bytes":       len(content),
        "risk_score":       risk_score,
        "severity":         severity,
        "malware_detected": malware_detected,
        "av_detail":        av_detail,
        "extension":        static_result["extension"],
        "findings":         static_result["findings"],
        "cached":           False,
    }

    # ── Cache result by content and extension ───────────────────────────────
    try:
        _REDIS.setex(cache_key, _CACHE_TTL, json.dumps(result))
    except Exception as exc:
        logger.warning("[manual_file_scan] Redis cache write failed: %s", exc)

    logger.info(
        "[manual_file_scan] Complete file_id=%s hash=%s risk=%.1f severity=%s malware=%s",
        file_id, file_hash[:16], risk_score, severity, malware_detected,
    )
    _persist_local_report(result)
    return result


def _persist_local_report(result: dict) -> None:
    """Make synchronous compatibility results retrievable via the owned Scan API."""
    from pathlib import Path
    from tasks import validate_scan_id
    scan_id = result["scan_id"]
    validate_scan_id(scan_id)
    result.update(is_placeholder=True, heuristic_only=True, automatic_decision=False, score_type="static_heuristic")
    directory = Path(_SHARED_DIR) / scan_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "risk_report.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(result, indent=2), encoding="utf-8")
    temporary.replace(path)


def queue_manual_file_scan(filename: str, content: bytes, user, db) -> dict:
    """Persist an owned upload before dispatching the bounded analysis chord."""
    from pathlib import Path
    from tasks.file_analysis import dispatch_file_analysis
    if not content:
        raise HTTPException(400, "Uploaded file is empty.")
    if len(content) > _MAX_FILE_BYTES:
        raise HTTPException(413, "Maximum file size is 50 MB.")
    scan_id = str(uuid.uuid4())
    safe_name = _sanitise_filename(filename)
    digest = _sha256_file(content)
    scan = Scan(id=scan_id, user_id=user.id, status="file_analysis_queued", url=None)
    db.add(scan)
    db.commit()
    directory = Path(_SHARED_DIR) / "files" / scan_id
    directory.mkdir(parents=True, exist_ok=False)
    try:
        payload = directory / "payload.bin"
        payload.write_bytes(content)
        metadata = {"scan_id": scan_id, "file_id": scan_id, "owner_user_id": user.id,
                    "filename": safe_name, "sha256": digest, "size": len(content)}
        (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        # Reuse only technical findings; each caller gets a new owned Scan/artifact.
        try:
            cached_raw = _REDIS.get(_cache_key(digest, _get_extension(safe_name)))
        except Exception:
            cached_raw = None
        result = json.loads(cached_raw) if cached_raw else {}
        if result.get("pipeline_version") == "file_static_v10_v1" and result.get("status") == "complete":
            result.update(scan_id=scan_id, file_id=scan_id, filename=safe_name, cached=True)
            from services.diagnostic_reports import save_report
            save_report(scan_id, result, "file_scan_done", owner_user_id=user.id)
            return {**result, "status": "file_scan_done"}
        job = dispatch_file_analysis(scan_id)
        return {"scan_id": scan_id, "file_id": scan_id, "status": "file_analysis_queued", "job_id": job.id}
    except Exception as exc:
        scan.status = "file_dispatch_failed"
        db.commit()
        raise HTTPException(503, "File analysis could not be queued; retry later.") from exc
