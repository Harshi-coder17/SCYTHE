"""Authenticated mailbox investigation and owner-scoped diagnostic reports."""
import hmac
import json
import logging
import os
import re
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from config import settings
from database.database import get_db
from database.models import Scan, User

logger = logging.getLogger(__name__)
email_router = APIRouter(prefix="/api/email", tags=["email"])
SHARED_DIR = settings.EMAIL_SHARED_DIR
_EMAIL_ID_RE = re.compile(r"^[a-zA-Z0-9_-][a-zA-Z0-9_.-]{0,127}$")

class EmailInvestigateRequest(BaseModel):
    email_id: str


def _validate_email_id(email_id: str) -> None:
    if not _EMAIL_ID_RE.fullmatch(email_id):
        raise HTTPException(422, "Invalid email_id format.")


def _read(email_id: str, name: str) -> dict:
    _validate_email_id(email_id)
    try:
        data = json.loads((Path(SHARED_DIR) / "emails" / email_id / name).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _authorize_email_artifact(email_id: str, current_user: User) -> None:
    owner = _read(email_id, "owner.json")
    # Email addresses supplied during self-registration are not proof of mailbox ownership.
    owner_id = owner.get("owner_user_id")
    if not owner_id or (owner_id != str(current_user.id) and getattr(current_user, "is_superuser", False) is not True):
        raise HTTPException(403, "Email ownership could not be established.")


def _queue(email_id: str, owner: User, db: Session) -> dict:
    # Shared-volume lock serializes duplicate delivery across API workers. The OS
    # releases it on worker exit; no stale Redis/file lease can block later retries.
    directory = Path(SHARED_DIR) / "emails" / email_id
    if not directory.is_dir():
        raise HTTPException(422, "Collected email directory is missing.")
    try:
        import fcntl
        with (directory / ".ingest.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            return _queue_locked(email_id, owner, db)
    except ImportError:
        # Cross-platform fallback for Windows where fcntl is not available (M34)
        try:
            import msvcrt
            with (directory / ".ingest.lock").open("a") as lock:
                msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    return _queue_locked(email_id, owner, db)
                finally:
                    try:
                        msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
        except (ImportError, OSError):
            return _queue_locked(email_id, owner, db)


def _queue_locked(email_id: str, owner: User, db: Session) -> dict:
    from services.email_investigation import run_email_investigation
    if not _read(email_id, "parsed.json"):
        raise HTTPException(422, "Parsed email is missing or invalid.")
    ownership = _read(email_id, "owner.json")
    scan_id = ownership.get("scan_id")
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == owner.id).first() if scan_id else None
    # An artifact identifies one immutable analysis attempt. Never resurrect a
    # timed-out/cancelled attempt by duplicate delivery or a repeated click.
    if scan:
        return {"email_id": email_id, "scan_id": scan.id, "status": scan.status, "duplicate": True}
    if scan is None:
        scan = Scan(id=str(uuid.uuid4()), user_id=owner.id, status="email_analysis_queued", url=None)
        db.add(scan)
    else:
        scan.status = "email_analysis_queued"
    db.commit()
    ownership["scan_id"] = scan.id
    path = Path(SHARED_DIR) / "emails" / email_id / "owner.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(ownership), encoding="utf-8")
    os.replace(temporary, path)
    try:
        result = run_email_investigation(email_id)
    except Exception:
        scan.status = "email_dispatch_failed"
        db.commit()
        raise
    return {**result, "scan_id": scan.id}


@email_router.post("/ingest")
def poller_ingest(payload: EmailInvestigateRequest, authorization: str = Header(default=""), db: Session = Depends(get_db)):
    # A dedicated token can only enqueue the single operator-bound mailbox. It is not a login token.
    token = settings.EMAIL_POLLER_TOKEN
    if len(token) < 32 or not hmac.compare_digest(authorization, f"Bearer {token}"):
        raise HTTPException(401, "Invalid mailbox ingestion credentials.")
    owner_id = settings.EMAIL_OWNER_USER_ID
    try:
        uuid.UUID(owner_id)
    except (ValueError, TypeError):
        raise HTTPException(503, "Mailbox owner has not been provisioned.")
    owner = db.query(User).filter(User.id == owner_id, User.is_active.is_(True)).first()
    binding = _read(payload.email_id, "owner.json")
    mailbox = settings.EMAIL_ADDRESS.strip().lower()
    if owner is None or not mailbox or binding.get("owner_user_id") != owner_id or binding.get("owner_email") != mailbox:
        raise HTTPException(403, "Email does not belong to the configured mailbox binding.")
    return _queue(payload.email_id, owner, db)


@email_router.post("/investigate")
def email_investigate(payload: EmailInvestigateRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _validate_email_id(payload.email_id)
    _authorize_email_artifact(payload.email_id, current_user)
    owner_id = _read(payload.email_id, "owner.json").get("owner_user_id")
    owner = db.query(User).filter(User.id == owner_id, User.is_active.is_(True)).first()
    if owner is None:
        raise HTTPException(403, "Mailbox owner is inactive or unavailable.")
    return _queue(payload.email_id, owner, db)


def _detail(email_id: str, db: Session, include_parsed: bool = False, scan_cache: dict = None) -> dict:
    binding = _read(email_id, "owner.json")
    parsed = _read(email_id, "parsed.json")
    metadata = parsed.get("metadata", {})
    scan_id = binding.get("scan_id")
    if scan_cache is not None and scan_id in scan_cache:
        scan = scan_cache[scan_id]
    else:
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == binding.get("owner_user_id")).first() if scan_id else None
    report = _read(email_id, "risk_report.json") or None
    if scan:
        try:
            canonical = Path(settings.SHARED_DIR) / str(uuid.UUID(scan.id)) / "risk_report.json"
            report = json.loads(canonical.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    result = {"email_id": email_id, "scan_id": scan_id, "status": scan.status if scan else "collected",
              "subject": metadata.get("subject"), "from_address": metadata.get("from_address"),
              "received_at": metadata.get("date"), "risk_report": report}
    if include_parsed:
        result["parsed"] = parsed
    return result


@email_router.get("")
def list_emails(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    root = Path(SHARED_DIR) / "emails"
    ids = []
    if root.exists():
        for item in root.iterdir():
            if item.is_dir() and _EMAIL_ID_RE.fullmatch(item.name):
                binding = _read(item.name, "owner.json")
                if binding.get("owner_user_id") == str(current_user.id):
                    ids.append(item.name)
    ids.sort(reverse=True)
    page_ids = ids[offset:offset + limit]

    # Pre-fetch scans in bulk to eliminate N+1 queries (H18)
    scan_ids = []
    for email_id in page_ids:
        b = _read(email_id, "owner.json")
        if b.get("scan_id"):
            scan_ids.append(b["scan_id"])
    scan_cache = {}
    if scan_ids:
        for scan in db.query(Scan).filter(Scan.id.in_(scan_ids), Scan.user_id == current_user.id).all():
            scan_cache[scan.id] = scan

    return {"emails": [_detail(item, db, scan_cache=scan_cache) for item in page_ids], "total": len(ids)}


@email_router.get("/{email_id}")
def get_email(email_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _authorize_email_artifact(email_id, current_user)
    return _detail(email_id, db, include_parsed=True)
