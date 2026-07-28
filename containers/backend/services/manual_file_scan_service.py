"""
services/manual_file_scan_service.py
=======================================
V10 Architecture — Dashboard Manual File Scan Service (GT Page 13).

Entry point: Dashboard scan.html → FastAPI → POST /api/scans/file (new route)

Flow (per GT Page 13):
  1. Dashboard uploads a file (PDF, DOCX, PNG, etc.)
  2. Generate SHA-256 hash of the file content
  3. Check Redis / Postgres for existing verdict for this hash
     → If found: return cached result immediately
  4. If new file:
     a. Save artifacts to /shared/files/{file_id}/
     b. Create Celery chord:
          Parallel: [hash_analysis_task, static_analysis_task, malware_analysis_task]
          Then:     content_analysis_task
          Then:     file_consistency_task (chord callback)
     c. Trigger risk_fusion
     d. Store Redis + Postgres
     e. Return result to dashboard

This service implements a simplified synchronous version that:
  - Computes SHA-256 hash
  - Checks Redis cache
  - Runs static analysis inline (no Celery) for the MVP
  - Stores the result in Postgres
  - Returns a full verdict immediately

Note: The full async Celery chord architecture is scaffolded here and
designed for easy migration once the file-scan tasks are implemented.
"""

import hashlib
import json
import logging
import os
import re
import uuid
from typing import Optional

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
        if s <= 20: return "Safe"
        elif s <= 40: return "Low"
        elif s <= 60: return "Medium"
        elif s <= 80: return "High"
        return "Critical"

    return {
        "score":    score,
        "severity": _severity(score),
        "findings": findings,
        "extension": ext,
    }


def _severity_label(score: float) -> str:
    if score <= 20: return "Safe"
    elif score <= 40: return "Low"
    elif score <= 60: return "Medium"
    elif score <= 80: return "High"
    return "Critical"


def _cache_key(file_hash: str) -> str:
    return f"filescan:hash:{file_hash}"


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

    # ── Redis cache check ────────────────────────────────────────────────────
    cached_raw = _REDIS.get(_cache_key(file_hash))
    if cached_raw:
        cached = json.loads(cached_raw)
        cached["cached"] = True
        logger.info(
            "[manual_file_scan] Cache hit hash=%s filename=%r", file_hash[:16], safe_name
        )
        return cached

    # ── Generate file_id and save artifacts ──────────────────────────────────
    file_id = str(uuid.uuid4())
    file_dir = _file_dir(file_id)
    os.makedirs(file_dir, exist_ok=True)

    dest_path = os.path.join(file_dir, safe_name)
    with open(dest_path, "wb") as f:
        f.write(content)

    # Save metadata.json alongside
    metadata = {
        "file_id":   file_id,
        "filename":  safe_name,
        "sha256":    file_hash,
        "size":      len(content),
        "path":      dest_path,
    }
    with open(os.path.join(file_dir, "metadata.json"), "w") as mf:
        json.dump(metadata, mf, indent=2)

    # ── Static analysis ──────────────────────────────────────────────────────
    static_result = _static_analysis(safe_name, content)
    risk_score = float(static_result["score"])
    severity   = static_result["severity"]

    # ── ClamAV scan (optional — fail-open) ──────────────────────────────────
    malware_detected = False
    av_detail = "Not scanned"
    try:
        from services.malware_scanner import scan_file_clamav
        is_clean, av_detail = scan_file_clamav(dest_path)
        if not is_clean:
            malware_detected = True
            risk_score = min(risk_score + 40, 100)
            static_result["findings"].append(f"ClamAV: {av_detail}")
            severity = _severity_label(risk_score)
    except Exception as exc:
        logger.warning("[manual_file_scan] ClamAV unavailable: %s", exc)
        av_detail = "Scanner unavailable"

    # ── Persist to Postgres ──────────────────────────────────────────────────
    if db is not None and user is not None:
        try:
            scan = Scan(
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

    # ── Cache result (by hash, so same file submitted again is instant) ──────
    try:
        _REDIS.setex(_cache_key(file_hash), _CACHE_TTL, json.dumps(result))
    except Exception as exc:
        logger.warning("[manual_file_scan] Redis cache write failed: %s", exc)

    logger.info(
        "[manual_file_scan] Complete file_id=%s hash=%s risk=%.1f severity=%s malware=%s",
        file_id, file_hash[:16], risk_score, severity, malware_detected,
    )
    return result
