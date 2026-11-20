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
FEATURE_NAMES_V3 = FEATURE_NAMES_V2 + (
    "tld_abuse_risk",
    "digit_ratio_host",
    "digit_ratio_url",
    "vowel_ratio_domain",
    "directory_depth",
    "path_longest_token_length",
    "has_credential_keyword",
    "consecutive_special_chars",
    "non_standard_port",
    "tld_in_subdomain",
)

HIGH_ABUSE_TLDS = frozenset({
    "top", "xyz", "icu", "buzz", "fit", "gq", "cf", "ga", "ml", "tk",
    "live", "shop", "work", "click", "rest", "country", "tokyo", "kim",
    "online", "site", "bid", "loan", "club", "vip", "men", "stream",
    "cc", "sbs", "cfd", "monster", "hair", "cam", "quest",
})
LOW_ABUSE_TLDS = frozenset({"gov", "edu", "mil", "int"})
COMMON_TLDS = frozenset({"com", "org", "net", "edu", "gov", "co", "io", "info", "app", "dev"})

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

CONFUSABLE_SUBS = (
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("0", "o"),
    ("1", "l"),
    ("3", "e"),
    ("5", "s"),
    ("@", "a"),
)

PROTECTED_BRANDS = frozenset({
    "microsoft", "google", "amazon", "paypal", "apple", "docusign",
    "netflix", "facebook", "instagram", "chase", "bankofamerica",
    "wellsfargo", "coinbase", "binance", "metamask", "phantom",
    "dropbox", "adobe", "salesforce", "crowdstrike", "okta"
})

_extractor = tldextract.TLDExtract(suffix_list_urls=())


def calc_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = collections.Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def check_confusable_homoglyph(host: str) -> dict:
    """
    Detect zero-day Latin/ASCII confusable homoglyphs (e.g. 'arnazon' for 'amazon',
    'clocusign' for 'docusign', 'crovvdfense' for 'crowdstrike', 'paypa1' for 'paypal').
    Returns dict with detected: bool, target_brand: str | None, confusable_token: str.
    """
    if not host:
        return {"detected": False, "target_brand": None, "source_token": ""}

    extracted = _extractor(host.lower())
    domain_part = (extracted.domain or "").lower()
    if not domain_part or domain_part in PROTECTED_BRANDS:
        return {"detected": False, "target_brand": None, "source_token": domain_part}

    # 1. Apply multi-character confusable substitutions (rn->m, vv->w, cl->d, etc.)
    normalized = domain_part
    for src, dst in CONFUSABLE_SUBS:
        normalized = normalized.replace(src, dst)

    if normalized != domain_part:
        for brand in PROTECTED_BRANDS:
            if normalized == brand or brand in normalized:
                return {
                    "detected": True,
                    "target_brand": brand,
                    "source_token": domain_part,
                    "normalized_token": normalized,
                }

    # 2. Check 1-edit distance for single character typosquatting/substitutions
    for brand in PROTECTED_BRANDS:
        if abs(len(domain_part) - len(brand)) <= 1:
            diffs = sum(1 for a, b in zip(domain_part, brand) if a != b) + abs(len(domain_part) - len(brand))
            if diffs == 1 and domain_part != brand:
                return {
                    "detected": True,
                    "target_brand": brand,
                    "source_token": domain_part,
                    "normalized_token": domain_part,
                }

    return {"detected": False, "target_brand": None, "source_token": domain_part}


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

    # V3 enhanced features
    suffix = (getattr(extracted, "suffix", "") or "").lower()
    if suffix in HIGH_ABUSE_TLDS or any(suffix.endswith("." + t) for t in HIGH_ABUSE_TLDS):
        tld_risk = 1.0
    elif suffix in LOW_ABUSE_TLDS or any(suffix.endswith("." + t) for t in LOW_ABUSE_TLDS):
        tld_risk = 0.0
    else:
        tld_risk = 0.2

    digit_ratio_host = round(sum(c.isdigit() for c in host) / max(len(host), 1), 4)
    digit_ratio_url = round(sum(c.isdigit() for c in canonical_url) / max(len(canonical_url), 1), 4)

    domain_only = (getattr(extracted, "domain", "") or "").lower()
    letters = [c for c in domain_only if c.isalpha()]
    vowel_ratio_domain = round(sum(c in "aeiou" for c in letters) / max(len(letters), 1), 4) if letters else 0.0

    directory_depth = parsed.path.count("/")
    path_tokens = re.split(r"[/._\-?=&]", parsed.path)
    path_longest_token = max((len(t) for t in path_tokens if t), default=0)

    full_path_query = (parsed.path + "?" + parsed.query).lower()
    has_cred_kw = int(any(kw in full_path_query for kw in SENSITIVE_KEYWORDS))

    consecutive_spec = int(bool(re.search(r"[-_.//]{2,}", canonical_url)))
    has_port = parsed.port is not None and parsed.port not in (80, 443)
    non_standard_port = int(bool(has_port))
    tld_in_sub = int(bool(subdomains and any(s.lower() in COMMON_TLDS for s in subdomains)))

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
        "tld_abuse_risk": tld_risk,
        "digit_ratio_host": digit_ratio_host,
        "digit_ratio_url": digit_ratio_url,
        "vowel_ratio_domain": vowel_ratio_domain,
        "directory_depth": directory_depth,
        "path_longest_token_length": path_longest_token,
        "has_credential_keyword": has_cred_kw,
        "consecutive_special_chars": consecutive_spec,
        "non_standard_port": non_standard_port,
        "tld_in_subdomain": tld_in_sub,
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
