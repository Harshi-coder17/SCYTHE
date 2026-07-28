"""
email_engine/poller.py
=======================
V10 Email Architecture — Email Collection Step 1.

Runs continuously, connects to Gmail / Outlook IMAP via OAuth2 XOAUTH2
or App Password (plain AUTH LOGIN), checks for new/unread emails,
and for each found email:
  1. Generates a deterministic email_id from Message-ID header.
  2. Calls collector.fetch_email() to retrieve the raw RFC822 bytes.
  3. Calls parser.parse_and_save() to store parsed.json.
  4. Calls url_extraction.extract_and_save() to store url_list.json.
  5. Calls attachment_handler.extract_and_save() to store attachments/.
  6. Optionally triggers the backend ingestion endpoint POST /api/email/investigate.

Environment variables consumed (from config.py / .env):
  EMAIL_IMAP_HOST       — e.g. imap.gmail.com  (default: imap.gmail.com)
  EMAIL_ADDRESS         — monitored mailbox address
  EMAIL_ACCESS_TOKEN    — OAuth2 Bearer token  (used when EMAIL_AUTH_MODE=oauth2)
  EMAIL_APP_PASSWORD    — App password         (used when EMAIL_AUTH_MODE=password)
  EMAIL_AUTH_MODE       — "oauth2" | "password"  (default: oauth2)
  EMAIL_POLL_INTERVAL   — seconds between polls  (default: 30)
  EMAIL_SHARED_DIR      — shared volume root      (default: /shared/scans)
  BACKEND_INGEST_URL    — internal URL to POST /api/email/investigate (optional)
"""

import hashlib
import imaplib
import logging
import os
import time
import email as email_lib
from email.message import Message
from typing import Optional

from config import settings

from email_engine import collector, parser, url_extraction, attachment_handler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (pulled from settings / env)
# ---------------------------------------------------------------------------

_IMAP_HOST:      str = os.getenv("EMAIL_IMAP_HOST",    "imap.gmail.com")
_EMAIL_ADDRESS:  str = os.getenv("EMAIL_ADDRESS",      "")
_ACCESS_TOKEN:   str = os.getenv("EMAIL_ACCESS_TOKEN", "")
_APP_PASSWORD:   str = os.getenv("EMAIL_APP_PASSWORD", "")
_AUTH_MODE:      str = os.getenv("EMAIL_AUTH_MODE",    "oauth2")   # "oauth2" | "password"
_POLL_INTERVAL:  int = int(os.getenv("EMAIL_POLL_INTERVAL", "30"))
_SHARED_DIR:     str = getattr(settings, "EMAIL_SHARED_DIR", "/shared/scans")
_BACKEND_URL:    str = os.getenv("BACKEND_INGEST_URL", "")  # e.g. http://backend:8000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_email_id(msg: Message) -> str:
    """
    Derive a stable, filesystem-safe email_id from the Message-ID header.
    Falls back to a hash of To + Date if Message-ID is absent.
    """
    msg_id: str = msg.get("Message-ID", "") or ""
    if not msg_id:
        # Fallback: hash of To + Date
        raw = f"{msg.get('To','')}-{msg.get('Date','')}-{msg.get('Subject','')}"
        msg_id = raw
    # SHA-256 hex, truncated to 32 chars to keep paths short
    return hashlib.sha256(msg_id.encode("utf-8", errors="replace")).hexdigest()[:32]


def _trigger_backend(email_id: str) -> None:
    """
    Fire POST /api/email/investigate to start the Celery chord.
    Fails silently so the poller never crashes on network issues.
    """
    if not _BACKEND_URL:
        logger.debug("[poller] BACKEND_INGEST_URL not set — skipping auto-ingest for %s", email_id)
        return
    try:
        import urllib.request
        import json
        url = f"{_BACKEND_URL.rstrip('/')}/api/email/investigate"
        data = json.dumps({"email_id": email_id}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info(
                "[poller] Backend ingestion triggered email_id=%s status=%d",
                email_id, resp.status,
            )
    except Exception as exc:
        logger.warning(
            "[poller] Backend ingest call failed for email_id=%s: %s",
            email_id, exc,
        )


# ---------------------------------------------------------------------------
# IMAP Connection
# ---------------------------------------------------------------------------

class EmailPoller:
    """
    Continuous IMAP poller.  Connects to the configured mailbox,
    searches for UNSEEN messages, and runs the collection pipeline
    for each new email found.
    """

    def __init__(self) -> None:
        self._imap: Optional[imaplib.IMAP4_SSL] = None
        self._processed: set[bytes] = set()  # IMAP UID bytes already handled

    # ── Connection management ──────────────────────────────────────────────

    def _connect(self) -> None:
        logger.info("[poller] Connecting to %s …", _IMAP_HOST)
        self._imap = imaplib.IMAP4_SSL(_IMAP_HOST, 993)

        if _AUTH_MODE == "oauth2":
            if not _ACCESS_TOKEN:
                raise RuntimeError(
                    "EMAIL_ACCESS_TOKEN is required when EMAIL_AUTH_MODE=oauth2"
                )
            auth_string = (
                f"user={_EMAIL_ADDRESS}\x01"
                f"auth=Bearer {_ACCESS_TOKEN}\x01\x01"
            )
            self._imap.authenticate("XOAUTH2", lambda _: auth_string.encode())
        else:
            if not _APP_PASSWORD:
                raise RuntimeError(
                    "EMAIL_APP_PASSWORD is required when EMAIL_AUTH_MODE=password"
                )
            self._imap.login(_EMAIL_ADDRESS, _APP_PASSWORD)

        self._imap.select("INBOX")
        logger.info("[poller] Connected and INBOX selected.")

    def _disconnect(self) -> None:
        if self._imap:
            try:
                self._imap.logout()
            except Exception:
                pass
            self._imap = None

    # ── Fetch new messages ─────────────────────────────────────────────────

    def _fetch_unseen_uids(self) -> list[bytes]:
        status, data = self._imap.search(None, "UNSEEN")
        if status != "OK" or not data or not data[0]:
            return []
        uid_list = [uid for uid in data[0].split() if uid not in self._processed]
        return uid_list

    def _fetch_raw(self, uid: bytes) -> Optional[bytes]:
        status, msg_data = self._imap.fetch(uid, "(RFC822)")
        if status != "OK" or not msg_data or msg_data[0] is None:
            return None
        return msg_data[0][1]

    # ── Per-email pipeline ─────────────────────────────────────────────────

    def _process_email(self, uid: bytes, raw_bytes: bytes) -> None:
        msg = email_lib.message_from_bytes(raw_bytes)
        email_id = _make_email_id(msg)

        logger.info(
            "[poller] Processing uid=%s email_id=%s subject=%r",
            uid, email_id, msg.get("Subject", "")[:80],
        )

        try:
            # Step 1: Parse raw email → parsed.json
            parser.parse_and_save(email_id=email_id, raw_bytes=raw_bytes, shared_dir=_SHARED_DIR)

            # Step 2: Extract & normalise URLs → url_list.json
            url_extraction.extract_and_save(email_id=email_id, raw_bytes=raw_bytes, shared_dir=_SHARED_DIR)

            # Step 3: Extract attachments → attachments/
            attachment_handler.extract_and_save(email_id=email_id, raw_bytes=raw_bytes, shared_dir=_SHARED_DIR)

            # Step 4: Trigger Celery chord via backend API
            _trigger_backend(email_id)

            self._processed.add(uid)
            logger.info("[poller] Pipeline complete for email_id=%s", email_id)

        except Exception:
            logger.exception("[poller] Pipeline failed for email_id=%s uid=%s", email_id, uid)

    # ── Main polling loop ──────────────────────────────────────────────────

    def run(self) -> None:
        """
        Blocking main loop.  Reconnects automatically on IMAP errors.
        """
        logger.info(
            "[poller] Starting — address=%s host=%s interval=%ds",
            _EMAIL_ADDRESS, _IMAP_HOST, _POLL_INTERVAL,
        )

        while True:
            try:
                if self._imap is None:
                    self._connect()

                uids = self._fetch_unseen_uids()
                if uids:
                    logger.info("[poller] Found %d new email(s).", len(uids))
                    for uid in uids:
                        raw_bytes = self._fetch_raw(uid)
                        if raw_bytes:
                            self._process_email(uid, raw_bytes)
                else:
                    logger.debug("[poller] No new emails.")

            except imaplib.IMAP4.abort:
                logger.warning("[poller] IMAP connection aborted — reconnecting …")
                self._disconnect()

            except Exception:
                logger.exception("[poller] Unexpected error — reconnecting in %ds …", _POLL_INTERVAL)
                self._disconnect()

            time.sleep(_POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Entry point (run as background process / Celery Beat task)
# ---------------------------------------------------------------------------

def start_polling() -> None:
    """Start the email poller.  Call this from celery_beat.py or a dedicated container."""
    EmailPoller().run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    start_polling()
