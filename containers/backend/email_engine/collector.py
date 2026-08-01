"""
email_engine/collector.py
==========================
V10 Email Architecture — Email Collection Step 1b.

Fetches the complete raw RFC822 email bytes from an IMAP mailbox by UID.
Called by poller.py after discovering a new UNSEEN message UID.

Returns RawEmail (bytes) to parser.py for structured conversion.

This module provides:
  fetch_by_uid()   → given an open IMAP connection + UID, returns raw bytes.
  collect()        → convenience function that opens a temporary IMAP session,
                     fetches a single email by UID, and closes the session.
"""

import email as email_lib
import imaplib
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_IMAP_HOST:     str = os.getenv("EMAIL_IMAP_HOST",    "imap.gmail.com")
_EMAIL_ADDRESS: str = os.getenv("EMAIL_ADDRESS",      "")
_ACCESS_TOKEN:  str = os.getenv("EMAIL_ACCESS_TOKEN", "")
_APP_PASSWORD:  str = os.getenv("EMAIL_APP_PASSWORD", "")
_AUTH_MODE:     str = os.getenv("EMAIL_AUTH_MODE",    "oauth2")


def _open_connection() -> imaplib.IMAP4_SSL:
    """Open and authenticate an IMAP4_SSL connection, select INBOX."""
    imap = imaplib.IMAP4_SSL(_IMAP_HOST, 993)

    if _AUTH_MODE == "oauth2":
        auth_string = (
            f"user={_EMAIL_ADDRESS}\x01"
            f"auth=Bearer {_ACCESS_TOKEN}\x01\x01"
        )
        imap.authenticate("XOAUTH2", lambda _: auth_string.encode())
    else:
        imap.login(_EMAIL_ADDRESS, _APP_PASSWORD)

    imap.select("INBOX")
    return imap


def fetch_by_uid(imap: imaplib.IMAP4_SSL, uid: bytes) -> Optional[bytes]:
    """
    Fetch the raw RFC822 bytes of the message with the given UID.

    Parameters
    ----------
    imap : An authenticated, open IMAP4_SSL connection with INBOX selected.
    uid  : The IMAP UID (bytes) of the target message.

    Returns
    -------
    Raw RFC822 bytes, or None if fetch failed.
    """
    try:
        status, data = imap.fetch(uid, "(RFC822)")
        if status != "OK" or not data or data[0] is None:
            logger.warning("[collector] Fetch failed for uid=%s status=%s", uid, status)
            return None
        raw: bytes = data[0][1]
        logger.debug("[collector] Fetched uid=%s size=%d bytes", uid, len(raw))
        return raw
    except Exception:
        logger.exception("[collector] Exception fetching uid=%s", uid)
        return None


def collect(uid: bytes) -> Optional[bytes]:
    """
    Open a temporary IMAP session, fetch one email by UID, close session.

    Intended for one-off fetches (e.g. testing or manual collection).
    For continuous polling, prefer keeping one persistent connection via
    EmailPoller (poller.py).

    Parameters
    ----------
    uid : IMAP UID bytes.

    Returns
    -------
    Raw RFC822 bytes, or None.
    """
    imap: Optional[imaplib.IMAP4_SSL] = None
    try:
        imap = _open_connection()
        return fetch_by_uid(imap, uid)
    except Exception:
        logger.exception("[collector] collect() failed for uid=%s", uid)
        return None
    finally:
        if imap:
            try:
                imap.logout()
            except Exception:
                pass


def get_email_headers(raw_bytes: bytes) -> dict:
    """
    Parse only the headers from raw RFC822 bytes (no body decode).
    Returns a flat dict of header-name → value.
    """
    msg = email_lib.message_from_bytes(raw_bytes)
    headers: dict[str, str] = {}
    for key in msg.keys():
        val = msg.get(key, "")
        headers[key.lower()] = str(val)
    return headers
