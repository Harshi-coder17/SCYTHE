"""
consistency_engine/email_consistency_engine.py
================================================
V10 Email Architecture — Chord Callback Step 5.

Called by:  tasks/email_consistency.py  (the Celery chord callback)
Input:      All 4 feature files from /shared/emails/{email_id}/:
              - header_features.json
              - url_features.json
              - attachment_features.json
              - content_features.json
Output:     {
                "overall_score":      int  (0-100),
                "overall_severity":   str,
                "classification":     str  ("phishing" | "suspicious" | "clean"),
                "confidence":         float (0.0-1.0),
                "scores": {
                    "header":     int,
                    "url":        int,
                    "attachment": int,
                    "content":    int,
                },
                "consistency_flags":  list[str],
                "all_reasons":        list[str],
                "signal_weights":     dict,
            }

Cross-Signal Correlation Logic (per GT Page 11):
  - Correlates header / body / URL / attachment evidence.
  - Identifies compound patterns that individually score low but together
    constitute a high-confidence phishing attempt.
  - Weights each sub-signal by its evidential quality:
      header       → authentication & identity    (weight 0.30)
      url          → threat intel & infra          (weight 0.30)
      attachment   → malware & extension analysis  (weight 0.25)
      content      → NLP phishing indicators       (weight 0.15)
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Signal weights (must sum to 1.0)
# ---------------------------------------------------------------------------

_SIGNAL_WEIGHTS: dict[str, float] = {
    "header":     0.30,
    "url":        0.30,
    "attachment": 0.25,
    "content":    0.15,
}

# Severity ladder (used to map numeric score → label)
_SEVERITY_RANK: dict[str, int] = {
    "Safe": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4,
}
_RANK_SEVERITY: dict[int, str] = {v: k for k, v in _SEVERITY_RANK.items()}


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


def _classification(score: int) -> str:
    if score >= 60:
        return "phishing"
    elif score >= 30:
        return "suspicious"
    return "clean"


# ---------------------------------------------------------------------------
# Cross-signal correlation rules
# ---------------------------------------------------------------------------

def _run_correlation_rules(
    header_score: int,
    url_score: int,
    attachment_score: int,
    content_score: int,
    header_block: dict,
    url_block: dict,
    attachment_block: dict,
    content_block: dict,
) -> tuple[list[str], int]:
    """
    Evaluate compound cross-signal rules.

    Returns (consistency_flags, bonus_score).
    Bonus score represents confidence uplift from correlated signals.
    """
    flags: list[str] = []
    bonus = 0

    # ── Rule 1: Auth failure + Urgency content → classic phishing ───────────
    auth_fail = header_score >= 40
    urgency = content_score >= 40
    if auth_fail and urgency:
        flags.append(
            "AUTH_FAIL+URGENCY: Authentication failure combined with urgent content — "
            "high phishing confidence (classic credential harvesting)."
        )
        bonus += 10

    # ── Rule 2: High URL risk + no attachments → phishing link campaign ─────
    high_url = url_score >= 50
    no_attachment = attachment_score == 0
    if high_url and no_attachment:
        flags.append(
            "HIGH_URL+NO_ATTACH: High-risk URL with no attachments — "
            "likely a phishing link directing to a credential capture page."
        )
        bonus += 8

    # ── Rule 3: Dangerous attachment + low header score → malware delivery ──
    dangerous_attach = attachment_score >= 60
    trusted_looking_header = header_score < 20
    if dangerous_attach and trusted_looking_header:
        flags.append(
            "DANGEROUS_ATTACH+TRUSTED_HEADER: Dangerous attachment from seemingly legitimate sender — "
            "possible targeted malware delivery (spear-phishing)."
        )
        bonus += 12

    # ── Rule 4: High content score + URL risk → multi-vector phishing ───────
    if content_score >= 50 and url_score >= 50:
        flags.append(
            "HIGH_CONTENT+HIGH_URL: Both content NLP and URL threat signals are elevated — "
            "coordinated multi-vector phishing attempt."
        )
        bonus += 10

    # ── Rule 5: Brand impersonation + auth failure ───────────────────────────
    identity_reasons = header_block.get("identity", {}).get("reasons", [])
    brand_impersonation_seen = any(
        "spoof" in r.lower() or "impersonat" in r.lower() or "brand" in r.lower()
        for r in identity_reasons
    )
    if brand_impersonation_seen and header_score >= 30:
        flags.append(
            "BRAND_IMPERSONATION+AUTH_FAIL: Brand/identity impersonation combined with "
            "authentication failure — high-confidence phishing sender."
        )
        bonus += 8

    # ── Rule 6: URL redirect chain + content credential theft ────────────────
    url_reasons = url_block.get("urls", {}).get("reasons", []) + url_block.get("infrastructure", {}).get("reasons", [])
    redirect_seen = any("redirect" in r.lower() or "chain" in r.lower() for r in url_reasons)
    cred_seen = any(
        "credential" in r.lower() or "password" in r.lower()
        for r in content_block.get("content", {}).get("reasons", [])
    )
    if redirect_seen and cred_seen:
        flags.append(
            "REDIRECT_CHAIN+CREDENTIAL_THEFT: URL redirect chain combined with credential "
            "theft language — phishing chain with evasion."
        )
        bonus += 10

    # ── Rule 7: YARA/macro attachment + high content score ───────────────────
    attach_reasons = attachment_block.get("attachments", {}).get("reasons", [])
    malware_attach = any(
        "yara" in r.lower() or "macro" in r.lower() or "malware" in r.lower()
        for r in attach_reasons
    )
    if malware_attach and content_score >= 40:
        flags.append(
            "MALWARE_ATTACH+PHISH_CONTENT: Malware/macro attachment combined with phishing "
            "content language — targeted malware-laced phishing email."
        )
        bonus += 12

    return flags, bonus


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class EmailConsistencyEngine:
    """
    Correlates all four email analysis signal streams and produces a
    unified consistency report with compound pattern detection.
    """

    @staticmethod
    def analyze(
        header_features: Optional[dict] = None,
        url_features: Optional[dict] = None,
        attachment_features: Optional[dict] = None,
        content_features: Optional[dict] = None,
    ) -> dict:
        """
        Correlate all four feature blocks and compute a final email verdict.

        Parameters
        ----------
        header_features     : Output of email_header_analysis task.
        url_features        : Output of email_url_analysis task.
        attachment_features : Output of email_attachment_analysis task.
        content_features    : Output of email_content_analysis task.

        Returns
        -------
        Full consistency report dict.
        """
        header_features     = header_features     or {}
        url_features        = url_features        or {}
        attachment_features = attachment_features or {}
        content_features    = content_features    or {}

        # ── Extract individual scores ──────────────────────────────────────
        header_score     = int(header_features.get("header_score",     0))
        url_score        = int(url_features.get("url_score",           0))
        attachment_score = int(attachment_features.get("attachment_score", 0))
        content_score    = int(content_features.get("content_score",   0))

        # ── Weighted overall score ─────────────────────────────────────────
        weighted_score = (
            header_score     * _SIGNAL_WEIGHTS["header"]     +
            url_score        * _SIGNAL_WEIGHTS["url"]        +
            attachment_score * _SIGNAL_WEIGHTS["attachment"] +
            content_score    * _SIGNAL_WEIGHTS["content"]
        )

        # ── Cross-signal correlation rules ─────────────────────────────────
        consistency_flags, bonus = _run_correlation_rules(
            header_score, url_score, attachment_score, content_score,
            header_features, url_features, attachment_features, content_features,
        )

        overall_score = min(int(weighted_score) + bonus, 100)
        overall_severity = _severity(overall_score)

        # ── Collect all reasons from all four signal blocks ────────────────
        all_reasons: list[str] = []
        for block_dict, keys in [
            (header_features, ["authentication", "identity"]),
            (url_features, ["urls", "infrastructure"]),
            (attachment_features, ["attachments"]),
            (content_features, ["content"]),
        ]:
            for key in keys:
                sub_block = block_dict.get(key, {})
                if isinstance(sub_block, dict):
                    all_reasons.extend(sub_block.get("reasons", []))

        # ── Confidence: high when multiple non-zero signals agree ──────────
        non_zero_signals = sum(
            1 for s in [header_score, url_score, attachment_score, content_score]
            if s > 0
        )
        confidence_base = non_zero_signals / 4.0
        # Boost confidence when cross-signal rules fired
        confidence_boost = min(len(consistency_flags) * 0.1, 0.3)
        confidence = round(min(confidence_base + confidence_boost, 1.0), 3)

        report = {
            "overall_score":    overall_score,
            "overall_severity": overall_severity,
            "classification":   _classification(overall_score),
            "confidence":       confidence,
            "scores": {
                "header":     header_score,
                "url":        url_score,
                "attachment": attachment_score,
                "content":    content_score,
            },
            "consistency_flags": consistency_flags,
            "all_reasons":       all_reasons,
            "signal_weights":    _SIGNAL_WEIGHTS,
        }

        logger.info(
            "[email_consistency_engine] overall_score=%d severity=%s "
            "classification=%s confidence=%.3f flags=%d",
            overall_score, overall_severity,
            report["classification"], confidence, len(consistency_flags),
        )
        return report
