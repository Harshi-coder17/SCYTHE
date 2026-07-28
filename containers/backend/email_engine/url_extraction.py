"""
email_engine/url_extraction.py
================================
V10 Email Architecture — Email Collection Step 3.

Extracts all URLs from a raw RFC822 email, then:
  - Decodes URL-encoded sequences (%xx)
  - Normalises schemes (http/https) and trailing slashes
  - Cleans tracking wrappers (Safelinks, MailChimp redirects, etc.)
  - Deduplicates the final list

Saves result as url_list.json at /shared/emails/{email_id}/url_list.json

Called by: email_engine/poller.py (Step 3)
Reads:     raw RFC822 bytes (from collector.py)
Writes:    /shared/{EMAIL_SHARED_DIR}/emails/{email_id}/url_list.json

url_list.json schema:
    {
        "email_id":    str,
        "url_count":   int,
        "urls":        list[str],     # clean, normalised URLs
        "raw_urls":    list[str],     # original extracted URLs (for audit)
        "tracking_unwrapped": int,    # how many safelink/redirects were cleaned
    }
"""

import json
import logging
import os
import re
from urllib.parse import unquote, urlparse, urlunparse, parse_qs, urlencode
from typing import Optional
import email as email_lib

from config import settings

logger = logging.getLogger(__name__)

_SHARED_DIR: str = getattr(settings, "EMAIL_SHARED_DIR", "/shared/scans")

# ---------------------------------------------------------------------------
# URL extraction regex — matches http(s) and ftp URLs in raw text
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r"""
    (?:https?|ftp)://                # scheme
    [^\s<>\"\'\]\[\(\)\{\}]+         # URL body (no whitespace / bracket chars)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Tracking / safelink wrappers to unwrap
# ---------------------------------------------------------------------------

# Microsoft Safelinks: https://nam04.safelinks.protection.outlook.com/?url=<encoded-url>&...
_SAFELINKS_RE = re.compile(
    r"https?://[a-z0-9.]+\.safelinks\.protection\.outlook\.com/\?.*?url=([^&]+)",
    re.IGNORECASE,
)

# MailChimp click-tracking: https://mailchi.mp/... or http://r.mailchimp.com/...
_MAILCHIMP_RE = re.compile(
    r"https?://(?:r\.mailchimp\.com|mailchi\.mp)/.*?(?:\?|&)u=([^&]+)",
    re.IGNORECASE,
)

# Generic redirect parameter: ?url=, ?redirect=, ?link=, ?target=, ?dest=
_GENERIC_REDIRECT_RE = re.compile(
    r"https?://\S+?[?&](?:url|redirect|link|target|dest(?:ination)?)=([^&\s\"']+)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _extract_raw_urls(text: str) -> list[str]:
    """Find all http(s)/ftp URLs in a plain-text string."""
    # Strip trailing punctuation that is unlikely part of URL
    urls = []
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?\"'")
        if url:
            urls.append(url)
    return urls


def _unwrap_tracking(url: str) -> tuple[str, bool]:
    """
    If url is a known tracking wrapper, return (inner_url, True).
    Otherwise return (url, False).
    """
    # Safelinks
    m = _SAFELINKS_RE.match(url)
    if m:
        return unquote(m.group(1)), True

    # MailChimp
    m = _MAILCHIMP_RE.match(url)
    if m:
        return unquote(m.group(1)), True

    # Generic redirect parameter
    m = _GENERIC_REDIRECT_RE.match(url)
    if m:
        return unquote(m.group(1)), True

    return url, False


def _normalise(url: str) -> Optional[str]:
    """
    Decode percent-encoding, normalise scheme/host to lowercase,
    remove default ports, and strip fragment identifiers.
    Returns None if the URL is not parseable.
    """
    try:
        url = unquote(url)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https", "ftp"):
            return None

        scheme = parsed.scheme.lower()
        netloc = (parsed.netloc or "").lower()
        # Strip default ports
        if netloc.endswith(":80") and scheme == "http":
            netloc = netloc[:-3]
        elif netloc.endswith(":443") and scheme == "https":
            netloc = netloc[:-4]

        # Rebuild without fragment (anchors are irrelevant for threat analysis)
        clean = urlunparse((scheme, netloc, parsed.path, parsed.params, parsed.query, ""))
        return clean if clean else None
    except Exception:
        return None


def _get_text_parts(raw_bytes: bytes) -> list[str]:
    """Extract all text/plain and text/html body parts from raw RFC822 bytes."""
    texts: list[str] = []
    try:
        msg = email_lib.message_from_bytes(raw_bytes)
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset("utf-8") or "utf-8"
                    try:
                        texts.append(payload.decode(charset, errors="replace"))
                    except (LookupError, UnicodeDecodeError):
                        texts.append(payload.decode("utf-8", errors="replace"))
    except Exception:
        logger.exception("[url_extraction] Failed to decode message body")
    return texts


def extract_urls(raw_bytes: bytes) -> dict:
    """
    Extract, decode, normalise, and deduplicate all URLs from a raw email.

    Returns a dict with keys: urls, raw_urls, tracking_unwrapped.
    """
    texts = _get_text_parts(raw_bytes)
    full_text = "\n".join(texts)

    raw_urls: list[str] = _extract_raw_urls(full_text)
    clean_urls: list[str] = []
    raw_set: set[str] = set()
    tracking_unwrapped = 0

    for raw in raw_urls:
        if raw in raw_set:
            continue
        raw_set.add(raw)

        # Unwrap tracking wrappers
        inner, was_wrapped = _unwrap_tracking(raw)
        if was_wrapped:
            tracking_unwrapped += 1

        normalised = _normalise(inner)
        if normalised and normalised not in clean_urls:
            clean_urls.append(normalised)

    return {
        "url_count":          len(clean_urls),
        "urls":               clean_urls,
        "raw_urls":           list(raw_set),
        "tracking_unwrapped": tracking_unwrapped,
    }


def extract_and_save(
    email_id: str,
    raw_bytes: bytes,
    shared_dir: Optional[str] = None,
) -> str:
    """
    Extract URLs from raw email bytes and persist url_list.json.

    Parameters
    ----------
    email_id   : Unique email identifier.
    raw_bytes  : Raw RFC822 bytes.
    shared_dir : Root of shared volume (default: EMAIL_SHARED_DIR).

    Returns
    -------
    Absolute path to the saved url_list.json.
    """
    shared_dir = shared_dir or _SHARED_DIR
    email_dir  = os.path.join(shared_dir, "emails", email_id)
    os.makedirs(email_dir, exist_ok=True)

    result = extract_urls(raw_bytes)
    result["email_id"] = email_id

    output_path = os.path.join(email_dir, "url_list.json")
    tmp_path    = output_path + ".tmp"

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, output_path)  # atomic write

    logger.info(
        "[url_extraction] url_list.json saved email_id=%s url_count=%d "
        "tracking_unwrapped=%d",
        email_id, result["url_count"], result["tracking_unwrapped"],
    )
    return output_path
