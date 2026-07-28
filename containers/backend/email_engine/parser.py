"""
email_engine/parser.py
=======================
V10 Email Architecture — Email Collection Step 2.

Converts raw RFC822 email bytes → Structured Email Object (MIME format).
Saves result as parsed.json at /shared/emails/{email_id}/parsed.json.

The structured object mirrors the existing services/email/email_collector.py
format so all downstream Celery tasks (email_header_analysis, etc.) can
consume it unchanged.

Data shape produced:
    {
        "metadata":        MetadataParser.parse(raw_bytes),
        "authentication":  AuthenticationParser.parse(raw_bytes),
        "received_chain":  ReceivedChainParser.parse(raw_bytes),
        "domain":          DomainParser.parse(raw_bytes),
        "attachments":     AttachmentParser.parse(raw_bytes),
        "content":         ContentParser.parse(raw_bytes),
    }

Called by: email_engine/poller.py (Step 2)
Reads:     raw RFC822 bytes (from collector.py)
Writes:    /shared/{EMAIL_SHARED_DIR}/emails/{email_id}/parsed.json
"""

import json
import logging
import os
from typing import Optional

from config import settings
from services.email.email_collector import parse_raw_email  # reuses the 6-parser pipeline

logger = logging.getLogger(__name__)

_SHARED_DIR: str = getattr(settings, "EMAIL_SHARED_DIR", "/shared/scans")


def _email_dir(email_id: str, shared_dir: str) -> str:
    return os.path.join(shared_dir, "emails", email_id)


def parse_raw_bytes(raw_bytes: bytes) -> dict:
    """
    Run all 6 parsers on raw RFC822 email bytes and return a
    unified structured email dict.

    Delegates to services/email/email_collector.parse_raw_email()
    which already orchestrates all six parser modules:
      MetadataParser, AuthenticationParser, ReceivedChainParser,
      DomainParser, AttachmentParser, ContentParser.

    Parameters
    ----------
    raw_bytes : Complete raw RFC822 email bytes.

    Returns
    -------
    Structured dict matching the parsed.json schema consumed by tasks.
    """
    try:
        return parse_raw_email(raw_bytes)
    except Exception:
        logger.exception("[parser] parse_raw_email() failed — returning empty structure")
        return {
            "metadata":       {},
            "authentication": {},
            "received_chain": {},
            "domain":         {},
            "attachments":    {},
            "content":        {},
        }


def parse_and_save(
    email_id: str,
    raw_bytes: bytes,
    shared_dir: Optional[str] = None,
) -> str:
    """
    Parse raw RFC822 email bytes and persist the structured JSON to disk.

    Parameters
    ----------
    email_id   : Unique identifier for this email (derived by poller.py).
    raw_bytes  : Raw RFC822 bytes from collector.py.
    shared_dir : Root of the shared volume (defaults to EMAIL_SHARED_DIR).

    Returns
    -------
    Absolute path to the saved parsed.json file.
    """
    shared_dir = shared_dir or _SHARED_DIR
    email_dir  = _email_dir(email_id, shared_dir)
    os.makedirs(email_dir, exist_ok=True)

    parsed = parse_raw_bytes(raw_bytes)

    output_path = os.path.join(email_dir, "parsed.json")
    tmp_path    = output_path + ".tmp"

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, output_path)  # atomic write

    logger.info(
        "[parser] parsed.json saved email_id=%s path=%s",
        email_id, output_path,
    )
    return output_path
