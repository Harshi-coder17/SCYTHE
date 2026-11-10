"""Local URL-only feature construction matching the fresh dataset contract.

This module is preparation for a future model adapter. It is deliberately not
called by risk_fusion and performs no DNS, browser, or threat-feed lookups.
Unknown domain bogon status remains ``None`` exactly as it does in training.
"""
from __future__ import annotations

import collections
import ipaddress
import math
import re
from urllib.parse import urlsplit, urlunsplit

import tldextract

FEATURE_VERSION = "scythe-url-features-v1"
FEATURE_NAMES = (
    "url_length", "host_length", "is_https", "is_ip_host", "subdomain_count",
    "hyphen_count", "digit_count", "special_count", "at_symbol",
    "question_mark_count", "path_length", "query_length", "has_punycode",
    "url_shortener_used", "is_bogon_space",
)
FEATURE_NAMES_V1 = FEATURE_NAMES
FEATURE_NAMES_V2 = FEATURE_NAMES_V1 + (
    "is_paas_subdomain", "subdomain_entropy", "brand_in_subdomain_mismatch",
)

SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "rebrand.ly",
})
PAAS_DOMAINS = frozenset({
    "vercel.app", "workers.dev", "pages.dev", "firebaseapp.com", "web.app",
    "netlify.app", "render.com", "azurewebsites.net", "github.io", "gitlab.io",
    "herokuapp.com", "glitch.me", "surge.sh", "weeblysite.com", "wixsite.com",
    "blogspot.com", "duckdns.org", "ngrok-free.app", "serveo.net", "loca.lt"
})
SENSITIVE_KEYWORDS = frozenset({
    "login", "signin", "verify", "verification", "account", "update", "security",
    "banking", "wallet", "phantom", "metamask", "cibc", "support", "auth",
    "recover", "seed", "passcode", "secure", "confirm", "portal", "helpdesk"
})

_extractor = tldextract.TLDExtract(suffix_list_urls=())


def calc_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = collections.Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def normalize_url(raw: str) -> str | None:
    """Apply the dataset's URL normalization; reject malformed/credential URLs."""
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if not raw or len(raw) > 8192:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or parsed.username or parsed.password:
            return None
        host = (parsed.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
        if not host or any(char.isspace() for char in host):
            return None
        try:
            is_ipv6 = ipaddress.ip_address(host).version == 6
        except ValueError:
            is_ipv6 = False
        authority_host = f"[{host}]" if is_ipv6 else host
        port = parsed.port
        netloc = authority_host if port is None or (scheme == "https" and port == 443) or (scheme == "http" and port == 80) else f"{authority_host}:{port}"
        return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError):
        return None


def observed_features(canonical_url: str, host: str) -> dict[str, int | float | None]:
    parsed = urlsplit(canonical_url)
    is_ip = 0
    bogon = None
    try:
        address = ipaddress.ip_address(host)
        is_ip = 1
        bogon = int(not address.is_global)
    except ValueError:
        pass
    extracted = _extractor(host)
    if hasattr(extracted, "top_domain_under_public_suffix"):
        group = extracted.top_domain_under_public_suffix or host
    else:
        group = getattr(extracted, "registered_domain", None) or host
    subdomains = [s for s in extracted.subdomain.split(".") if s and s.lower() != "www"] if extracted.subdomain else []
    
    sub_str = extracted.subdomain.lower() if extracted.subdomain else ""
    entropy = calc_entropy(sub_str)
    tokens = set(re.split(r"[-_.]", sub_str))
    brand_kw = int(bool(sub_str and any(kw in tokens or kw in sub_str for kw in SENSITIVE_KEYWORDS)))
    is_paas = int(group in PAAS_DOMAINS or any(host.endswith("." + p) for p in PAAS_DOMAINS))

    return {
        "url_length": len(canonical_url),
        "host_length": len(host),
        "is_https": int(parsed.scheme == "https"),
        "is_ip_host": is_ip,
        "subdomain_count": len(subdomains),
        "hyphen_count": canonical_url.count("-"),
        "digit_count": sum(char.isdigit() for char in canonical_url),
        "special_count": sum(not char.isalnum() for char in canonical_url),
        "at_symbol": int("@" in canonical_url),
        "question_mark_count": canonical_url.count("?"),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "has_punycode": int("xn--" in host),
        "url_shortener_used": int(group in SHORTENERS),
        "is_bogon_space": bogon,
        "is_paas_subdomain": is_paas,
        "subdomain_entropy": round(entropy, 4),
        "brand_in_subdomain_mismatch": brand_kw,
    }


def build_url_feature_vector(raw_url: str, feature_names: tuple[str, ...] | list[str] | None = None) -> dict:
    """Return an ordered feature result, or an explicit unavailable result."""
    canonical = normalize_url(raw_url)
    names = list(feature_names if feature_names is not None else FEATURE_NAMES)
    common = {"feature_version": FEATURE_VERSION, "feature_names": names}
    if canonical is None:
        return {**common, "status": "unavailable", "reason": "invalid_http_url", "canonical_url": None, "values": None}
    try:
        host = urlsplit(canonical).hostname or ""
        features = observed_features(canonical, host)
        values = [features[name] for name in names]
        return {**common, "status": "observed", "reason": None, "canonical_url": canonical, "values": values}
    except (ValueError, UnicodeError):
        return {**common, "status": "unavailable", "reason": "feature_extraction_failed", "canonical_url": canonical, "values": None}
