import os
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File, Form
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import User, Scan
from auth.dependencies import get_current_user
from config import settings

from schemas.quick_scan import QuickScanRequest, QuickScanResponse
from schemas.stage2 import Stage2Request, Stage2Response
from schemas.full_scan import FullScanRequest, FullScanResponse

from services.quickscan import run_quickscan
from services.stage2_analysis import run_stage2_analysis, _validate_scan_id, _scan_dir
from services.manual_url_scan_service import run_manual_url_scan
from services.manual_file_scan_service import run_manual_file_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])

# Whitelist of allowed scan artifacts to prevent path traversal / sensitive data leakage
_ALLOWED_ARTIFACTS = {
    "browser.html",
    "browser.png",
    "sandbox.html",           # written by sandbox_analysis.py (V8/V10 Change 3)
    "sandbox.png",
    "sandbox_fullpage.png",
    "risk_report.json",
    "browser_features.json",
    "consistency_report.json",
    "sandbox_metadata.json",
    "ece_report.json",        # V8/V10 alias for consistency_report.json (Change 4)
    "network.har",            # Playwright HAR capture from sandbox (V10 Page 8)
}



def _sanitize_html_content(html: str) -> str:
    """
    Sanitize captured raw phishing HTML for safe viewing inside an analyst iframe/dashboard.
    Strips active script execution elements, event handler attributes, and dangerous URI schemes.
    """
    try:
        import nh3
        return nh3.clean(html)
    except ImportError:
        logger.warning("nh3 not installed! Falling back to stripping text.")
        return html.replace("<", "&lt;").replace(">", "&gt;")
    except Exception as e:
        logger.warning("HTML sanitization error: %s, returning stripped text", e)
        return html.replace("<", "&lt;").replace(">", "&gt;")


@router.post("/quick", response_model=QuickScanResponse)
def quick_scan(
    payload: QuickScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        result = run_quickscan(payload=payload, user=current_user, db=db)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except HTTPException:
        raise
    except Exception:
        # Full details go to the server log only -- a raw str(e) in the
        # HTTP response can leak internal paths, DB errors, or stack
        # info to the caller.
        logger.exception(
            "Quick scan failed for url=%s user_id=%s", payload.url, current_user.id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Quick scan failed. Please try again shortly.",
        )

    return result


@router.post("/full", response_model=FullScanResponse)
def full_scan(
    payload: FullScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    url_str = str(payload.url)
    
    # 1. Quick cache check
    quick_result = run_quickscan(payload=QuickScanRequest(url=url_str), user=current_user, db=db)
    qr_dict = quick_result if isinstance(quick_result, dict) else quick_result.model_dump()
    if qr_dict.get("status") == "cached":
        return FullScanResponse(
            scan_id="cached", job_id="cached", status="COMPLETE",
            url=url_str, captured_by="server",
            screenshot_saved_path=None
        )
        
    # 2. Server-side capture
    from services.capture import capture_url
    import base64
    
    png_bytes, html_content = capture_url(url_str)
    b64_png = base64.b64encode(png_bytes).decode('ascii')
    
    # 3. Call stage2_analysis natively
    stage2_req = Stage2Request(
        url=payload.url,
        screenshot_base64=b64_png,
        html=html_content,
        tab_id=None
    )
    
    try:
        st2_resp = run_stage2_analysis(payload=stage2_req, user=current_user, db=db)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except HTTPException:
        raise
    except Exception:
        logger.exception("Full scan failed for url=%s user_id=%s", url_str, current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Full scan failed. Please try again shortly.",
        )
    
    return FullScanResponse(
        scan_id=st2_resp.scan_id,
        job_id=st2_resp.job_id,
        status=st2_resp.status,
        url=st2_resp.url,
        screenshot_saved_path=st2_resp.screenshot_saved_path,
        queued_at=st2_resp.queued_at,
        captured_by="server"
    )


@router.post("/stage2", response_model=Stage2Response)
def stage2_scan(
    payload: Stage2Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Asynchronous, screenshot-based deep analysis.
    Flow: validate request -> decode base64 screenshot -> save to shared
          Docker volume -> queue Celery job (sandbox_analysis / consistency /
          risk_fusion) -> return immediately with a job/status reference.
    """
    if not payload.screenshot_base64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing screenshot data.",
        )

    try:
        result = run_stage2_analysis(payload=payload, user=current_user, db=db)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "Stage 2 scan failed for url=%s user_id=%s", payload.url, current_user.id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stage 2 scan failed. Please try again shortly.",
        )

    return result


# Email investigation endpoint moved to api/email_routes.py
# mounted at POST /api/email/investigate (correct V10 prefix)


# ── GT Page 13: Dashboard Manual URL Scan ─────────────────────────────────────
# Handles both quick (synchronous CyberIntel + LightGBM) and deep (Celery
# chord via Stage 2) scan types from the dashboard scan.html page.

@router.post("/manual-url")
def manual_url_scan(
    url: str = Form(..., description="Target URL to scan"),
    scan_type: str = Form("quick", description="'quick' or 'deep'"),
    screenshot_base64: str = Form("", description="Base64 PNG — required for deep scan"),
    html: str = Form("", description="DOM HTML snapshot — required for deep scan"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    POST /api/scans/manual-url

    Dashboard manual URL scan entry point (GT Page 13).
    Routes to 'quick' (synchronous) or 'deep' (async Celery chord) scan
    based on the scan_type field.

    Quick: returns full verdict immediately.
    Deep:  returns job_id for WebSocket polling.
    """
    try:
        return run_manual_url_scan(
            url=url,
            scan_type=scan_type,
            screenshot_base64=screenshot_base64,
            html=html,
            tab_id=None,
            user=current_user,
            db=db,
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "Manual URL scan failed url=%s scan_type=%s user_id=%s",
            url, scan_type, current_user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Manual URL scan failed. Please try again shortly.",
        )


# ── GT Page 13: Dashboard Manual File Scan ────────────────────────────────────
# Accepts an uploaded file, computes SHA-256, checks Redis cache, runs static
# analysis (magic bytes, extension, MIME, malware signatures, ClamAV), stores
# the result in Postgres, and returns a full verdict immediately.

@router.post("/file")
async def manual_file_scan(
    file: UploadFile = File(..., description="File to scan (PDF, DOCX, PNG, EXE …)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    POST /api/scans/file

    Dashboard manual file scan entry point (GT Page 13).
    Performs static analysis, optional ClamAV scan, and SHA-256 hash caching.
    Returns a synchronous full verdict.
    """
    MAX_UPLOAD = 50 * 1024 * 1024  # 50 MB — enforced in service too, but guard here
    content = await file.read()
    if len(content) > MAX_UPLOAD:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large ({len(content)} bytes). Maximum is 50 MB.",
        )

    try:
        return run_manual_file_scan(
            filename=file.filename or "uploaded_file",
            content=content,
            user=current_user,
            db=db,
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "Manual file scan failed filename=%r user_id=%s",
            file.filename, current_user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File scan failed. Please try again shortly.",
        )


@router.get("/{scan_id}")
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve metadata and risk report (if completed) for a specific scan.
    """
    try:
        _validate_scan_id(scan_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or scan.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    report = None
    report_path = os.path.join(_scan_dir(scan_id), "risk_report.json")
    if os.path.exists(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
        except Exception:
            pass

    return {
        "scan_id": scan.id,
        "url": scan.url,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "severity": scan.severity,
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
        "risk_report": report,
    }


@router.get("/{scan_id}/artifacts/{artifact_name}")
def get_scan_artifact(
    scan_id: str,
    artifact_name: str,
    sanitized: bool = Query(True, description="Whether to sanitize HTML artifacts against XSS before serving"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # ── Path-traversal guard: scan_id must be a valid UUID ────────────────
    try:
        _validate_scan_id(scan_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # ── Ownership check ───────────────────────────────────────────────────
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or scan.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    # ── Artifact allowlist (path-traversal / data-leakage protection) ─────
    if artifact_name not in _ALLOWED_ARTIFACTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Artifact '{artifact_name}' is not available for download.",
        )

    # ── Build and verify file path ─────────────────────────────────────────
    file_path = os.path.join(_scan_dir(scan_id), artifact_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found.")

    if artifact_name == "browser.html":

        if not sanitized:
            is_su = getattr(current_user, "is_superuser", False) or (
                current_user.email in getattr(settings, "SUPERUSER_EMAILS", [])
            )
            if not is_su:
                logger.warning(
                    "[AUDIT_ALERT] Unauthorized attempt to download unsanitized HTML artifact %s by user %s (id=%s)",
                    artifact_name,
                    current_user.email,
                    current_user.id,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Serving unsanitized raw HTML artifacts requires superuser privileges.",
                )
            logger.warning(
                "[AUDIT_LOG] Superuser %s (id=%s) downloaded unsanitized HTML artifact for scan %s",
                current_user.email,
                current_user.id,
                scan_id,
            )

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw_html = f.read()
        content = _sanitize_html_content(raw_html) if sanitized else raw_html
        headers = {
            "Content-Security-Policy": "sandbox; default-src 'none'; img-src data: blob: 'self'; style-src 'unsafe-inline' 'self';",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Content-Disposition": 'inline; filename="captured_phishing_page.html"',
        }
        return Response(content=content, media_type="text/html", headers=headers)

    return FileResponse(file_path, filename=artifact_name)