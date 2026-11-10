"""Offline parser-to-email-detector contract, using SCYTHE's URL helper."""
from services.model_features.url_features import build_url_feature_vector


def build_email_url_evidence(parsed: dict, url_manifest: dict | None = None) -> dict:
    content = parsed.get("content", {})
    body_urls = content.get("extracted_urls")
    manifest_urls = (url_manifest or {}).get("urls")
    discovered = isinstance(body_urls, list) or isinstance(manifest_urls, list)
    raw_values = []
    for block in (body_urls, manifest_urls):
        if isinstance(block, list):
            raw_values.extend(item for item in block if isinstance(item, str))
    # URL order, de-duplication and invalid-input reporting are deterministic.
    records = []
    seen = set()
    for raw in sorted(set(raw_values)):
        vector = build_url_feature_vector(raw)
        identity = vector.get("canonical_url") or raw
        if identity in seen:
            continue
        seen.add(identity)
        values = dict(zip(vector["feature_names"], vector["values"])) if vector.get("values") is not None else None
        records.append({"url": raw, "canonical_url": vector.get("canonical_url"),
                        "status": vector["status"], "reason": vector.get("reason"), "features": values})
    observations = [item["features"] for item in records if item["status"] == "observed"]
    aggregate = {
        "url_count": len(observations) if discovered else None,
        "shortener_used": any(item["url_shortener_used"] for item in observations) if observations else None,
        "ip_address_url": any(item["is_ip_host"] for item in observations) if observations else None,
        "https": all(item["is_https"] for item in observations) if observations else None,
        # This legacy rule name means punycode syntax, not confirmed impersonation.
        "homoglyph": any(item["has_punycode"] for item in observations) if observations else None,
        "longest_url_length": max((item["url_length"] for item in observations), default=None),
        "blacklisted": None, "typosquatting": None, "domain_age_days": None, "redirect_count": None,
    }
    availability = {key: "observed" if value is not None else "unavailable" for key, value in aggregate.items()}
    count = parsed.get("received_chain", {}).get("received_count")
    routing = {"hop_count": count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None,
               "ip_blacklisted": None, "asn_reputation": None, "reverse_dns_exists": None,
               "country_matches_sender": None}
    return {"contract_version": "email_url_diagnostics_v1", "urls": aggregate, "routing": routing,
            "records": records, "feature_availability": availability,
            "routing_availability": {key: "observed" if value is not None else "unavailable" for key, value in routing.items()},
            "invalid_url_count": sum(item["status"] == "unavailable" for item in records),
            "discovery_status": "observed" if discovered else "unavailable",
            "punycode_semantics": "syntax_only_not_confirmed_brand_impersonation",
            "provider_policy": "no_network_calls; unavailable enrichment remains null"}
