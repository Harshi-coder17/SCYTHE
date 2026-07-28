"""
ai_engine/phishing_nlp.py
==========================
V10 Email Architecture — AI-powered NLP phishing detector.

Used by:   tasks/email_content_analysis.py  (Child Process P4)
Input:     subject (str), body (str), metadata (dict)
Output:    {
               "score":       int  (0-100),
               "severity":    str  ("Safe" | "Low" | "Medium" | "High" | "Critical"),
               "detections":  list[str],   # individual signal labels
               "reasons":     list[str],   # human-readable explanations
           }

Detection strategy (rule-based NLP, no external model required):
  ─ Urgency / fear language         (weight 25)
  ─ Credential theft patterns       (weight 35)
  ─ Brand impersonation keywords    (weight 30)
  ─ Social engineering patterns     (weight 20)
  ─ Financial scam indicators       (weight 20)
  ─ Subject-body consistency check  (weight 10)
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Keyword signal banks
# ---------------------------------------------------------------------------

_URGENCY_PATTERNS: list[str] = [
    r"\burgent\b", r"\bimmediate(?:ly)?\b", r"\baction required\b",
    r"\bact now\b", r"\bwithin \d+ hours?\b", r"\bexpires?\b",
    r"\bdeadline\b", r"\bsuspended?\b", r"\bdeactivated?\b",
    r"\byour account (?:has been|will be)\b", r"\blimited time\b",
    r"\blast chance\b", r"\bfailure to (?:respond|comply|act)\b",
    r"\baccount (?:locked|blocked|restricted)\b",
    r"\bsecurity alert\b", r"\bunusual (?:activity|sign-in|login)\b",
]

_CREDENTIAL_THEFT_PATTERNS: list[str] = [
    r"\benter (?:your )?(?:password|credentials|login|pin)\b",
    r"\bverify (?:your )?(?:identity|account|email|details)\b",
    r"\bconfirm (?:your )?(?:account|identity|password|details)\b",
    r"\bupdate (?:your )?(?:password|login|credentials|billing|payment)\b",
    r"\bclick (?:here )?to (?:verify|confirm|reset|login|sign in)\b",
    r"\bsign in to (?:verify|secure|unlock)\b",
    r"\bpassword (?:reset|expired|expiring)\b",
    r"\bwe (?:need|require) (?:your )?(?:information|details|credentials)\b",
    r"\bprovide (?:your )?(?:social security|ssn|date of birth|credit card)\b",
]

_BRAND_IMPERSONATION: list[str] = [
    # Common brand names in phishing context
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "bank of america", "wells fargo", "chase", "citibank", "hsbc",
    "fedex", "ups", "dhl", "usps", "irs", "hmrc", "nhs",
    "facebook", "instagram", "whatsapp", "linkedin", "twitter",
    "dropbox", "docusign", "zoom", "office 365", "outlook", "onedrive",
    "adobe", "godaddy", "binance", "coinbase", "blockchain",
]

_SOCIAL_ENGINEERING_PATTERNS: list[str] = [
    r"\bwe (?:noticed|detected|observed)\b",
    r"\byour (?:account|information) (?:was|has been)\b",
    r"\bsomeone (?:tried|attempted) to\b",
    r"\bunauthorized (?:access|activity|login)\b",
    r"\bfor (?:your )?(?:security|safety|protection)\b",
    r"\bto (?:protect|secure) your account\b",
    r"\bdo not share (?:this|your password)\b",
    r"\bthis (?:email|message) was sent (?:to|by)\b",
    r"\bif you did not (?:request|authorize|initiate)\b",
    r"\bplease (?:do not|don't) ignore this\b",
    r"\bcontact (?:us|support) immediately\b",
]

_FINANCIAL_SCAM_PATTERNS: list[str] = [
    r"\byou (?:have |'ve )?(?:won|been selected|been chosen)\b",
    r"\bcongratulations\b.*\b(?:prize|reward|gift|winner)\b",
    r"\bunclaimed\b.*\b(?:funds|refund|inheritance|payment)\b",
    r"\bmillion dollars?\b", r"\binheritance\b",
    r"\btransfer (?:funds?|money|amount)\b",
    r"\brefund (?:is )?(?:available|pending|ready)\b",
    r"\bcash prize\b", r"\bgift card\b",
    r"\bpay (?:a )?small fee\b", r"\bprocessing fee\b",
    r"\btax refund\b", r"\bbeneficiary\b",
]


def _compile_patterns(raw: list[str]) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in raw]


_RE_URGENCY = _compile_patterns(_URGENCY_PATTERNS)
_RE_CRED = _compile_patterns(_CREDENTIAL_THEFT_PATTERNS)
_RE_SOCIAL = _compile_patterns(_SOCIAL_ENGINEERING_PATTERNS)
_RE_FINANCIAL = _compile_patterns(_FINANCIAL_SCAM_PATTERNS)


def _count_hits(text: str, patterns: list[re.Pattern]) -> int:
    return sum(1 for p in patterns if p.search(text))


def _check_brand_impersonation(text: str) -> tuple[int, list[str]]:
    """Return (hit_count, list_of_brand_names_found)."""
    found = [b for b in _BRAND_IMPERSONATION if b in text.lower()]
    return len(found), found


def _subject_body_consistency(subject: str, body: str) -> bool:
    """
    Returns True if there is a consistency mismatch that raises suspicion.
    E.g. subject claims urgent but body has minimal text (empty phishing lure).
    """
    if not subject or not body:
        return False
    subj_lower = subject.lower()
    body_stripped = body.strip()
    # Suspicious if subject has urgency keywords but body is very short
    urgency_in_subject = any(p.search(subj_lower) for p in _RE_URGENCY)
    body_too_short = len(body_stripped) < 80
    return urgency_in_subject and body_too_short


def _severity(score: int) -> str:
    if score <= 20:
        return "Safe"
    elif score <= 40:
        return "Low"
    elif score <= 60:
        return "Medium"
    elif score <= 80:
        return "High"
    return "Critical"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(
    subject: Optional[str] = "",
    body: Optional[str] = "",
    metadata: Optional[dict] = None,
) -> dict:
    """
    Run NLP-based phishing analysis against the email subject + body.

    Parameters
    ----------
    subject  : Email subject line.
    body     : Plain-text or HTML body (stripped).
    metadata : Optional dict with extra fields (e.g. sender_name).

    Returns
    -------
    dict with keys: score (int), severity (str), detections (list[str]),
                    reasons (list[str]).
    """
    subject = subject or ""
    body = body or ""
    metadata = metadata or {}

    combined_text = f"{subject} {body}"

    score = 0
    detections: list[str] = []
    reasons: list[str] = []

    # ── 1. Urgency / fear language ──────────────────────────────────────────
    urgency_hits = _count_hits(combined_text, _RE_URGENCY)
    if urgency_hits >= 2:
        score += 25
        detections.append("urgency_language")
        reasons.append(
            f"Urgency/fear language detected ({urgency_hits} pattern(s)): "
            "creates pressure to act without thinking."
        )
    elif urgency_hits == 1:
        score += 12
        detections.append("urgency_language_weak")
        reasons.append("Minor urgency language detected in email.")

    # ── 2. Credential theft patterns ───────────────────────────────────────
    cred_hits = _count_hits(combined_text, _RE_CRED)
    if cred_hits >= 2:
        score += 35
        detections.append("credential_theft")
        reasons.append(
            f"Credential theft language detected ({cred_hits} pattern(s)): "
            "solicits passwords, personal data, or login actions."
        )
    elif cred_hits == 1:
        score += 18
        detections.append("credential_theft_weak")
        reasons.append("Possible credential harvesting language in email.")

    # ── 3. Brand impersonation ──────────────────────────────────────────────
    brand_count, brand_names = _check_brand_impersonation(combined_text)
    if brand_count >= 2:
        score += 30
        detections.append("brand_impersonation")
        reasons.append(
            f"Multiple brand names referenced ({', '.join(brand_names[:3])}): "
            "common in impersonation attacks."
        )
    elif brand_count == 1:
        score += 12
        detections.append("brand_mention")
        reasons.append(f"Brand name referenced ({brand_names[0]}): verify sender legitimacy.")

    # ── 4. Social engineering patterns ─────────────────────────────────────
    social_hits = _count_hits(combined_text, _RE_SOCIAL)
    if social_hits >= 2:
        score += 20
        detections.append("social_engineering")
        reasons.append(
            f"Social engineering tactics detected ({social_hits} pattern(s)): "
            "manipulates trust or authority."
        )
    elif social_hits == 1:
        score += 10
        detections.append("social_engineering_weak")
        reasons.append("Mild social engineering language observed.")

    # ── 5. Financial scam indicators ───────────────────────────────────────
    financial_hits = _count_hits(combined_text, _RE_FINANCIAL)
    if financial_hits >= 1:
        score += 20
        detections.append("financial_scam")
        reasons.append(
            f"Financial scam indicators detected ({financial_hits} pattern(s)): "
            "lottery wins, inheritance offers, or fee requests."
        )

    # ── 6. Subject-body consistency mismatch ───────────────────────────────
    if _subject_body_consistency(subject, body):
        score += 10
        detections.append("subject_body_mismatch")
        reasons.append(
            "Suspicious subject-body mismatch: urgent subject with minimal body content "
            "(common in minimal phishing lures)."
        )

    score = min(score, 100)

    result = {
        "score": score,
        "severity": _severity(score),
        "detections": detections,
        "reasons": reasons,
    }

    logger.debug(
        "[phishing_nlp] subject=%r score=%d severity=%s detections=%s",
        subject[:60], score, result["severity"], detections,
    )
    return result
