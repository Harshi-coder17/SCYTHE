"""
services/manual_url_scan_service.py
=====================================
V10 Architecture — Dashboard Manual URL Scan Service (GT Page 13).

Entry point: Dashboard scan.html → FastAPI → POST /api/scans/quick or /api/scans/full

Flow (per GT Page 13):
  1. Dashboard submits URL + scan_type ("quick" | "deep")
  2. This service creates a scan_id, checks Redis/Postgres cache
  3. If already exists → return cached result
  4. If scan_type == "quick":
       a. CyberIntel threat intelligence lookup
       b. LightGBM risk model (via run_risk_fusion)
       c. Store result to Postgres + Redis cache
       d. Return result immediately to dashboard
  5. If scan_type == "deep":
       a. Server-side browser capture (capture.py)
       b. Submit Stage 2 Celery chord (browser_features + sandbox_analysis)
       c. Risk Fusion → WebSocket → Dashboard update
       d. Return job_id immediately, dashboard polls via WebSocket

The existing services/quickscan.py handles case (4) and services/stage2_analysis.py
handles case (5). This service wraps both in a unified dashboard-facing interface
with explicit scan_type routing and enriched response metadata for dashboard rendering.
"""

import logging
from urllib.parse import urlparse

from fastapi import HTTPException, status

from config import settings
from schemas.quick_scan import QuickScanRequest, QuickScanResponse
from schemas.stage2 import Stage2Request, Stage2Response
from services.quickscan import run_quickscan
from services.stage2_analysis import run_stage2_analysis

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

SCAN_TYPE_QUICK = "quick"
SCAN_TYPE_DEEP  = "deep"

_ALLOWED_SCAN_TYPES = {SCAN_TYPE_QUICK, SCAN_TYPE_DEEP}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_url(url: str) -> str:
    """
    Basic URL validation — ensures a parseable http(s) URL.
    Returns the normalised URL string, or raises HTTPException(400).
    """
    url = url.strip()
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL must not be empty.",
        )
    # Prepend scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("No host")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL: {url!r}. Must be a valid http(s) URL.",
        )
    return url


def _validate_scan_type(scan_type: str) -> str:
    scan_type = (scan_type or SCAN_TYPE_QUICK).lower().strip()
    if scan_type not in _ALLOWED_SCAN_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan_type {scan_type!r}. Must be 'quick' or 'deep'.",
        )
    return scan_type


# ---------------------------------------------------------------------------
# Quick scan branch (synchronous, returns immediately)
# ---------------------------------------------------------------------------

def _run_quick_scan(url: str, user, db) -> dict:
    """
    CyberIntel + LightGBM quick verdict.
    Wraps services/quickscan.run_quickscan() and converts to dashboard-friendly dict.
    """
    payload = QuickScanRequest(url=url)
    result: QuickScanResponse = run_quickscan(payload=payload, user=user, db=db)

    return {
        "scan_type":     SCAN_TYPE_QUICK,
        "status":        "complete",
        "url":           url,
        "risk_score":    result.risk_score,
        "risk_level":    result.risk_level.value if hasattr(result.risk_level, "value") else str(result.risk_level),
        "is_placeholder": result.is_placeholder,
        "is_whitelisted": result.is_whitelisted,
        "cached":        result.cached,
        "reasons":       result.reasons or [],
        "domain":        result.domain,
    }


# ---------------------------------------------------------------------------
# Deep scan branch (asynchronous, returns job_id for WebSocket polling)
# ---------------------------------------------------------------------------

def _run_deep_scan(url: str, screenshot_base64: str, html: str, tab_id, user, db) -> dict:
    """
    Server-side browser capture → Stage 2 Celery chord dispatch.
    Wraps services/stage2_analysis.run_stage2_analysis().
    """
    payload = Stage2Request(
        url=url,
        screenshot_base64=screenshot_base64,
        html=html,
        tab_id=tab_id,
    )
    try:
        result: Stage2Response = run_stage2_analysis(payload=payload, user=user, db=db)
    except (ValueError, HTTPException):
        raise
    except Exception:
        logger.exception("[manual_url_scan] Deep scan failed for url=%s", url)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Deep scan pipeline failed. Please retry.",
        )

    return {
        "scan_type": SCAN_TYPE_DEEP,
        "status":    result.status if isinstance(result.status, str) else result.status.value,
        "url":       url,
        "scan_id":   result.scan_id,
        "job_id":    result.job_id,
        "message":   "Deep scan queued. Connect to WebSocket for live updates.",
    }


# ---------------------------------------------------------------------------
# Public service entry point
# ---------------------------------------------------------------------------

def run_manual_url_scan(
    url: str,
    scan_type: str = SCAN_TYPE_QUICK,
    screenshot_base64: str = "",
    html: str = "",
    tab_id=None,
    user=None,
    db=None,
) -> dict:
    """
    Unified dashboard manual URL scan handler.

    Parameters
    ----------
    url               : Target URL submitted from dashboard scan.html.
    scan_type         : "quick" (synchronous) or "deep" (asynchronous Celery chord).
    screenshot_base64 : Base64 PNG screenshot — required for deep scan.
    html              : DOM HTML snapshot — required for deep scan.
    tab_id            : Browser tab ID (optional, deep scan only).
    user              : Authenticated user ORM object.
    db                : SQLAlchemy session.

    Returns
    -------
    Result dict. Quick scan: complete result immediately.
    Deep scan: job_id + status for WebSocket polling.
    """
    url       = _validate_url(url)
    scan_type = _validate_scan_type(scan_type)

    logger.info(
        "[manual_url_scan] url=%s scan_type=%s user_id=%s",
        url, scan_type, getattr(user, "id", "unknown"),
    )

    if scan_type == SCAN_TYPE_QUICK:
        return _run_quick_scan(url=url, user=user, db=db)

    # Deep scan — requires screenshot
    if not screenshot_base64:
        # Try server-side capture if no screenshot provided
        try:
            from services.capture import capture_url
            import base64
            png_bytes, html_content = capture_url(url)
            screenshot_base64 = base64.b64encode(png_bytes).decode("ascii")
            html = html_content or html
        except Exception as exc:
            logger.warning("[manual_url_scan] Server-side capture failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Deep scan requires a screenshot. "
                    "Provide screenshot_base64 or ensure the server-side capture service is running."
                ),
            )

    return _run_deep_scan(
        url=url,
        screenshot_base64=screenshot_base64,
        html=html,
        tab_id=tab_id,
        user=user,
        db=db,
    )
