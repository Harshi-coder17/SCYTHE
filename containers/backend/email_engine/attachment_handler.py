"""
email_engine/attachment_handler.py
====================================
V10 Email Architecture — Email Collection Step 4.

Extracts attachments (PDF, DOCX, PNG, etc.) from a raw RFC822 email and
stores them at:
  /shared/emails/{email_id}/attachments/{safe_filename}

Also writes an attachments_manifest.json cataloguing all extracted files
with their filename, size, MIME type, SHA-256 hash, and storage path.

Called by: email_engine/poller.py (Step 4)
Reads:     raw RFC822 bytes (from collector.py)
Writes:
  /shared/{EMAIL_SHARED_DIR}/emails/{email_id}/attachments/{filename}
  /shared/{EMAIL_SHARED_DIR}/emails/{email_id}/attachments_manifest.json

attachments_manifest.json schema:
    {
        "email_id":         str,
        "attachment_count": int,
        "attachments": [
            {
                "filename":    str,
                "safe_name":   str,     # filesystem-safe sanitised name
                "mime_type":   str,
                "size_bytes":  int,
                "sha256":      str,
                "path":        str,     # absolute path on shared volume
            },
            ...
        ]
    }
"""

import email as email_lib
import hashlib
import json
import logging
import os
import re
from typing import Optional

from config import settings

logger = logging.getLogger(__name__)

_SHARED_DIR: str = getattr(settings, "EMAIL_SHARED_DIR", "/shared/scans")

# Maximum individual attachment size we'll write to disk (10 MB)
_MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _sanitise_filename(filename: str) -> str:
    """
    Produce a filesystem-safe version of the attachment filename.
    Removes path separators, null bytes, and limits length to 200 chars.
    Preserves the original extension.
    """
    if not filename:
        return "attachment"

    # Replace path-traversal chars and null bytes
    safe = re.sub(r'[\\/:*?"<>|\x00]', "_", filename)
    # Collapse multiple consecutive underscores/spaces
    safe = re.sub(r"[_ ]{2,}", "_", safe).strip("._")
    # Limit total length
    if len(safe) > 200:
        root, ext = os.path.splitext(safe)
        safe = root[: 200 - len(ext)] + ext

    return safe or "attachment"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_attachment_part(part) -> bool:
    """Return True if an email.message.Message part is an attachment."""
    disposition = part.get("Content-Disposition", "") or ""
    if "attachment" in disposition.lower():
        return True
    # Some emails mark files as inline but with a filename
    if part.get_filename():
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_attachments(raw_bytes: bytes) -> list[dict]:
    """
    Extract all attachment payloads from raw RFC822 email bytes.

    Returns a list of dicts, each with:
        filename, mime_type, size_bytes, sha256, data (bytes)
    """
    attachments: list[dict] = []
    seen_hashes: set[str] = set()

    try:
        msg = email_lib.message_from_bytes(raw_bytes)
    except Exception:
        logger.exception("[attachment_handler] Failed to parse email bytes")
        return attachments

    for part in msg.walk():
        if not _is_attachment_part(part):
            continue

        raw_filename: str = part.get_filename() or "attachment"
        mime_type: str = part.get_content_type() or "application/octet-stream"

        try:
            payload: Optional[bytes] = part.get_payload(decode=True)
        except Exception:
            logger.warning("[attachment_handler] Failed to decode payload for %r", raw_filename)
            continue

        if not payload:
            continue

        size = len(payload)
        if size > _MAX_ATTACHMENT_BYTES:
            logger.warning(
                "[attachment_handler] Attachment %r skipped — size %d bytes exceeds limit %d bytes",
                raw_filename, size, _MAX_ATTACHMENT_BYTES,
            )
            continue

        sha256 = _sha256_bytes(payload)
        if sha256 in seen_hashes:
            logger.debug("[attachment_handler] Duplicate attachment skipped: %r", raw_filename)
            continue
        seen_hashes.add(sha256)

        attachments.append({
            "filename":   raw_filename,
            "mime_type":  mime_type,
            "size_bytes": size,
            "sha256":     sha256,
            "data":       payload,
        })

    return attachments


def extract_and_save(
    email_id: str,
    raw_bytes: bytes,
    shared_dir: Optional[str] = None,
) -> str:
    """
    Extract all attachments from a raw email and write them to disk.
    Also writes attachments_manifest.json.

    Parameters
    ----------
    email_id   : Unique email identifier.
    raw_bytes  : Raw RFC822 bytes.
    shared_dir : Root of shared volume (default: EMAIL_SHARED_DIR).

    Returns
    -------
    Absolute path to the saved attachments_manifest.json.
    """
    shared_dir   = shared_dir or _SHARED_DIR
    email_dir    = os.path.join(shared_dir, "emails", email_id)
    attach_dir   = os.path.join(email_dir, "attachments")
    os.makedirs(attach_dir, exist_ok=True)

    raw_attachments = extract_attachments(raw_bytes)

    manifest_entries: list[dict] = []

    for att in raw_attachments:
        safe_name = _sanitise_filename(att["filename"])
        dest_path = os.path.join(attach_dir, safe_name)

        # If a file with the same safe name already exists, append hash prefix
        if os.path.exists(dest_path):
            name_root, ext = os.path.splitext(safe_name)
            safe_name = f"{name_root}_{att['sha256'][:8]}{ext}"
            dest_path = os.path.join(attach_dir, safe_name)

        with open(dest_path, "wb") as f:
            f.write(att["data"])

        entry = {
            "filename":   att["filename"],
            "safe_name":  safe_name,
            "mime_type":  att["mime_type"],
            "size_bytes": att["size_bytes"],
            "sha256":     att["sha256"],
            "path":       dest_path,
        }
        manifest_entries.append(entry)
        logger.debug(
            "[attachment_handler] Saved %r → %s (%d bytes)",
            att["filename"], dest_path, att["size_bytes"],
        )

    manifest = {
        "email_id":         email_id,
        "attachment_count": len(manifest_entries),
        "attachments":      manifest_entries,
    }

    manifest_path = os.path.join(email_dir, "attachments_manifest.json")
    tmp_path      = manifest_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, manifest_path)  # atomic write

    logger.info(
        "[attachment_handler] attachments_manifest.json saved email_id=%s count=%d",
        email_id, len(manifest_entries),
    )
    return manifest_path
