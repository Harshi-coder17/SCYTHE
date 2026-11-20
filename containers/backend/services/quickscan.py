"""
services/quickscan.py
======================
Quick scan service: synchronous pre-flight threat assessment.

Security hardening:
  - is_placeholder is mapped from the risk fusion result onto the response
    schema so the browser extension can render a neutral state.
  - Placeholder scores are NOT written to Redis cache:
    caching a random number would create a false consistency loop where
    every request for that domain within the TTL window receives the same
    fabricated score, giving an artificial appearance of determinism.
  - Only real, non-placeholder verdicts are cached. The cache TTL for real
    verdicts is kept at 5 minutes here (Stage 1 preliminary); the full
    1-hour cache is written by Risk Fusion (Stage 4) after the complete
    pipeline completes.
"""

import json
import hashlib
import logging
import urllib.parse
from urllib.parse import urlparse, parse_qs

import os
import redis
import tldextract

from config import settings
from database.models import Scan
from risk_fusion import run_risk_fusion
from schemas.quick_scan import QuickScanRequest, QuickScanResponse, RiskLevel
from services.model_features.url_features import normalize_url, check_confusable_homoglyph
from services.threat_feeds.feed_syncer import query_threat_feed

logger = logging.getLogger(__name__)

_redis_client = redis.from_url(settings.REDIS_URL)

# Stage-1 preliminary cache TTL (5 min).
# Stage-4 Risk Fusion overwrites with the authoritative 1-hour verdict.
_CACHE_TTL_SECONDS = 300


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.netloc and not parsed.scheme:
        parsed = urlparse("http://" + url)
    hostname = parsed.hostname
    if hostname:
        return hostname.lower()
    netloc = parsed.netloc or url
    if "@" in netloc:
        netloc = netloc.split("@")[-1]
    return netloc.split(":")[0].lower()


def _normalize_url_for_cache(url: str) -> str:
    return normalize_url(url) or url


def _cache_key(url: str) -> str:
    policy = {"allowlist": settings.TRUSTED_ALLOWLIST_DOMAINS,
              "release": settings.MODEL_RELEASE_CHECKSUMS_SHA256 if settings.MODEL_RELEASE_ENABLED else "disabled",
              "cache_contract": 3}
    digest = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
    return f"quickscan:url:{digest}:{_normalize_url_for_cache(url)}"


# Subdomains and domains hosting arbitrary user-generated content (UGC),
# user file uploads, or public multi-tenant pages that must NEVER be
# auto-whitelisted purely on parent domain reputation:
_UGC_EXCLUSION_PATTERNS = frozenset({
    # File storage / raw file download endpoints:
    "files.slack.com",
    "drive.google.com",
    "docs.google.com",
    "sites.google.com",
    "storage.googleapis.com",
    "storage.cloud.google.com",
    "dl.dropboxusercontent.com",
    "dropbox.com",
    "1drv.ms",
    "onedrive.live.com",
    "sharepoint.com",
    "wetransfer.com",
    "cdn.discordapp.com",
    "media.discordapp.net",
    "s3.amazonaws.com",
    "core.windows.net",
    "azureedge.net",
    "cloudapp.azure.com",
    "cloudapp.net",
    "digitaloceanspaces.com",
    "r2.dev",
    "r2.cloudflarestorage.com",
    "backblazeb2.com",
    "supabase.co",
    # Public multi-tenant hosting / PaaS / user website creators:
    "notion.site",
    "force.com",
    "my.site.com",
    "salesforce-sites.com",
    "github.io",
    "githubusercontent.com",
    "googleusercontent.com",
    "gitlab.io",
    "firebaseapp.com",
    "web.app",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "herokuapp.com",
    "azurewebsites.net",
    "glitch.me",
    "replit.dev",
    "replit.app",
    # URL Shorteners & Dynamic Redirectors (hide arbitrary destinations):
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "rb.gy",
    "s.id",
    "linktr.ee",
    "qrco.de",
    # Public Form Builders (frequently abused for credential harvesting):
    "forms.gle",
    "forms.office.com",
    "typeform.com",
})


def _load_tranco_top10k() -> frozenset[str]:
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "data", "tranco_top10k.txt"),
        os.path.join(os.getcwd(), "data", "tranco_top10k.txt"),
        "/app/data/tranco_top10k.txt",
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    domains = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
                logger.info("[quickscan] Loaded %d Tranco Top 10K domains from %s", len(domains), path)
                return frozenset(domains)
            except Exception as e:
                logger.warning("[quickscan] Failed reading Tranco file %s: %s", path, e)
    logger.warning("[quickscan] Tranco Top 10K list file not found in candidates: %s", candidates)
    return frozenset()


_TRANCO_TOP_10K = _load_tranco_top10k()

_REDIRECT_PARAMS = frozenset({
    "q", "url", "u", "redirect", "redirect_url", "redirect_uri",
    "target", "dest", "destination", "next", "r", "link", "to", "out",
    "goto", "return_url"
})


def _get_open_redirect_target(url: str, current_reg_domain: str) -> str | None:
    """
    Detects if a URL on a trusted domain wraps an outbound redirect to an external target.
    E.g. https://www.google.com/url?q=https://evil-phishing.com
    """
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for p, vals in qs.items():
            if p.lower() in _REDIRECT_PARAMS:
                for raw_val in vals:
                    val = raw_val.strip()
                    for _ in range(3):
                        unquoted = urllib.parse.unquote(val)
                        if unquoted == val:
                            break
                        val = unquoted.strip()
                    if val.startswith(("http://", "https://", "//")):
                        target_ext = tldextract.extract(val)
                        target_reg = getattr(target_ext, "top_domain_under_public_suffix", None) or target_ext.registered_domain
                        if target_reg and current_reg_domain and target_reg.lower() != current_reg_domain.lower():
                            return val
    except Exception:
        pass
    return None


def _check_trusted_infrastructure(url: str, domain: str) -> tuple[bool, str]:
    """
    Evaluates whether a URL belongs to verified core infrastructure of a trusted
    or top-ranked global domain, while explicitly refusing to auto-whitelist
    user-generated content (UGC), file downloads, or multi-tenant hosting endpoints.
    """
    try:
        ext = tldextract.extract(url)
        fqdn = ext.fqdn.lower()
        reg_domain = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
        reg_domain = reg_domain.lower() if reg_domain else ""
    except Exception:
        fqdn = domain.lower()
        reg_domain = domain.lower()

    # 1. UGC & Multi-Tenant gate: if the FQDN matches an excluded pattern,
    # never auto-whitelist — require full scanning.
    if any(fqdn == p or fqdn.endswith("." + p) for p in _UGC_EXCLUSION_PATTERNS):
        return False, "UGC/Shared-Hosting endpoint requires full scanning"

    # Exclude AWS S3 buckets in any region (*.s3.*.amazonaws.com, *.s3-*.amazonaws.com)
    if fqdn.endswith(".amazonaws.com") and ("s3" in fqdn.split(".amazonaws.com")[0]):
        return False, "AWS S3 storage endpoint requires full scanning"

    # 2. Open Redirect gate: if a trusted domain has a parameter redirecting
    # to an external destination, DO NOT auto-allowlist the wrapper!
    redirect_target = _get_open_redirect_target(url, reg_domain)
    if redirect_target:
        return False, f"Outbound redirect wrapper to external target: {redirect_target}"

    # 3. Check explicit trusted allowlist from settings
    trusted_list = getattr(settings, "TRUSTED_ALLOWLIST_DOMAINS", [])
    if any(reg_domain == td or fqdn == td or fqdn.endswith("." + td) for td in trusted_list):
        return True, f"Verified infrastructure of trusted domain: {reg_domain or fqdn}"

    # 3. Check Tranco Top 10K ranking
    if reg_domain and reg_domain in _TRANCO_TOP_10K:
        return True, f"Verified infrastructure of Tranco Top 10K global domain: {reg_domain}"

    return False, ""


def run_quickscan(payload: QuickScanRequest, user, db) -> QuickScanResponse:
    url = str(payload.url)
    from services.url_policy import validate_fetch_url, UnsafeURL
    try:
        validate_fetch_url(url)
    except UnsafeURL as e:
        raise ValueError(f"URL is unsafe or points to a non-public address: {e}")

    domain = _domain_from_url(url)
    result = {}
    cyberintel_result = {}

    # ── Redis cache check ──────────────────────────────────────────────────
    # Only real verdicts are stored here (see caching logic below), so a
    # cache hit always contains a trustworthy is_placeholder=False result.
    cached_raw = _redis_client.get(_cache_key(url))
    if cached_raw:
        cached = json.loads(cached_raw)
        cached["url"] = url
        cached["domain"] = domain
        cached["cached"] = True
        return QuickScanResponse(**cached)

    is_whitelisted = False
    whitelist_reason = ""

    # ── Tier-0 Global Threat Intel Feed check (<1ms) ──────────────────────
    is_feed_threat, feed_reason, feed_meta = query_threat_feed(_redis_client, url)
    if is_feed_threat:
        risk_score = 100.0
        risk_level = RiskLevel.CRITICAL
        reasons = [f"Tier-0 Threat Intelligence: {feed_reason}"]
        is_placeholder = False
        cyberintel_blocked = True
    else:
        is_whitelisted, whitelist_reason = _check_trusted_infrastructure(url, domain)

        if is_whitelisted:
            risk_score = 0.0
            risk_level = RiskLevel.SAFE
            reasons = [whitelist_reason or "Domain is on the trusted allowlist."]
            is_placeholder = False
        else:
            # ── Check zero-day Latin/ASCII confusable homoglyphs ────────────
            homoglyph_info = check_confusable_homoglyph(domain)
            if homoglyph_info.get("detected"):
                target_brand = homoglyph_info.get("target_brand")
                src_token = homoglyph_info.get("source_token")
                risk_score = 95.0
                risk_level = RiskLevel.CRITICAL
                reasons = [f"Homoglyph brand impersonation detected: domain token '{src_token}' deceptively mimics protected brand '{target_brand}'"]
                is_placeholder = False
                cyberintel_blocked = True
            else:
                # ── V8/V10: CyberIntel early gate (runs before LightGBM) ────────────
                # If any threat-intel feed (VT, SafeBrowsing, …) flags this URL,
                # mark it CRITICAL immediately and skip the placeholder scorer.
                # Fail-open: if CyberIntel itself is unavailable (missing API keys,
                # network timeout, etc.) we log a warning and fall through to
                # run_risk_fusion() exactly as before — zero behaviour change on
                # failure.
                cyberintel_result = {}
                try:
                    from cyberintel.runner import run_cyberintel
                    cyberintel_result = run_cyberintel(url)
                    ci_iocs = cyberintel_result.get("iocs", [])
                    if ci_iocs:
                        risk_score = 100.0
                        risk_level = RiskLevel.CRITICAL
                        is_placeholder = False
                        reasons = [
                            f"Threat intel: {ioc['type']} flagged "
                            f"{ioc.get('detail', ioc.get('value', ''))}"
                            for ioc in ci_iocs
                        ]
                        cyberintel_blocked = True
                    else:
                        cyberintel_blocked = False
                except Exception as _ci_exc:
                    logger.warning(
                        "[quickscan] CyberIntel check failed for %s — falling back "
                        "to run_risk_fusion(): %s",
                        url, _ci_exc,
                    )
                    cyberintel_blocked = False

                if not cyberintel_blocked:
                    result = run_risk_fusion({"url": url, "domain": domain})
                    risk_score = result["risk_score"]
                    risk_level = RiskLevel(result["risk_level"])
                    is_placeholder = result.get("is_placeholder", True)  # fail-closed: unknown → placeholder
                    reasons = result.get("explanations") or []
            if not reasons:
                if is_placeholder:
                    reasons = ["Score generated by placeholder model — treat as unverified."]
                else:
                    reasons = []

    scan = Scan(
        user_id=user.id,
        url=url,
        status="quick_scan_done",
        risk_score=risk_score,
        severity=risk_level.value if risk_level != RiskLevel.SAFE else None,
    )
    db.add(scan)
    db.commit()

    # ── V8/V10: Alert pipeline dispatch from Quick Scan ──────────────────
    # Fire alert_pipeline_task for real (non-placeholder) HIGH/CRITICAL
    # findings. risk_fusion_task already does this for Stage 2 deep scans;
    # this covers the case where CyberIntel alone raises a CRITICAL flag
    # before any Stage 2 scan is ever triggered.
    # Wrapped in try/except so a Celery broker outage never breaks the
    # synchronous Quick Scan HTTP response.
    _ALERT_SEVERITIES = {"HIGH", "CRITICAL"}
    if risk_level.value in _ALERT_SEVERITIES and not is_placeholder:
        try:
            from tasks.alert_pipeline import alert_pipeline_task
            _alert_report = {
                "scan_id": scan.id,
                "risk_score": risk_score,
                "severity": risk_level.value,
                "is_placeholder": False,
                "explanations": reasons,
                "iocs": cyberintel_result.get("iocs", []) if cyberintel_result else [],
            }
            alert_pipeline_task.delay(scan.id, _alert_report)
            logger.info(
                "[quickscan] alert_pipeline_task dispatched for scan %s "
                "(severity=%s)", scan.id, risk_level.value
            )
        except Exception:
            logger.exception(
                "[quickscan] Failed to dispatch alert_pipeline_task for "
                "scan %s — alert suppressed but scan result still returned",
                scan.id,
            )

    response = QuickScanResponse(
        url=url,
        domain=domain,
        risk_level=risk_level,
        risk_score=risk_score,
        is_whitelisted=is_whitelisted,
        cached=False,
        is_placeholder=is_placeholder,
        model_version=result.get("model_version"),
        contract_version=result.get("contract_version"),
        availability=result.get("availability"),
        reasons=reasons,
    )

    # ── Security Hardening: NEVER cache placeholder scores ────────────
    # Caching a random number would make every user who hits the same domain
    # within the TTL window receive the identical fabricated score, creating
    # a false appearance of deterministic confidence.
    # Only cache when is_placeholder is False (real model verdict).
    if not is_placeholder:
        _redis_client.setex(
            _cache_key(url),
            _CACHE_TTL_SECONDS,
            response.model_dump_json(),
        )
    else:
        logger.debug(
            "[quickscan] Skipping Redis cache for %s — is_placeholder=True "
            "(random score must not be persisted as a real verdict)",
            url,
        )

    return response
