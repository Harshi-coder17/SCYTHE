"""Offline URL parser/feature/detector contract tests."""
from unittest.mock import patch

from services.email.url_features import build_email_url_evidence
from services.email.detectors.url_detector import URLDetector
from services.email.detectors.infrastructure_detector import InfrastructureDetector


def test_extracted_urls_reach_real_rules_without_network_or_fake_enrichment():
    parsed = {"content": {"extracted_urls": ["http://192.0.2.10/login", "https://bit.ly/fixture", "https://bit.ly/fixture#fragment"]},
              "received_chain": {"received_count": 3}}
    with patch("socket.getaddrinfo", side_effect=AssertionError("No network allowed")):
        evidence = build_email_url_evidence(parsed, {"urls": ["http://192.0.2.10/login"]})
    assert evidence["urls"]["url_count"] == 2
    assert evidence["urls"]["ip_address_url"] and evidence["urls"]["shortener_used"]
    assert evidence["urls"]["https"] is False
    assert evidence["urls"]["blacklisted"] is None
    assert evidence["urls"]["domain_age_days"] is None
    assert evidence["feature_availability"]["domain_age_days"] == "unavailable"
    result = URLDetector().detect({"urls": evidence["urls"]})
    assert result["score"] == 60  # Only observed shortener/IP/plain-HTTP rules.
    assert evidence["routing"]["hop_count"] == 3
    assert evidence["routing"]["asn_reputation"] is None


def test_missing_fields_are_unavailable_and_not_safe_provider_facts():
    evidence = build_email_url_evidence({})
    assert evidence["discovery_status"] == "unavailable"
    assert evidence["urls"]["url_count"] is None
    assert evidence["urls"]["https"] is None
    assert URLDetector().detect({"urls": evidence["urls"]})["score"] == 0
    assert InfrastructureDetector().detect({"routing": evidence["routing"], "domain": {"dnssec_enabled": None}})["score"] == 0
    # Zero here means no observed rule fired, not a safe final verdict.
    assert all(status == "unavailable" for status in evidence["feature_availability"].values())


def test_empty_url_list_is_observed_absence_and_invalid_urls_are_reported():
    empty = build_email_url_evidence({"content": {"extracted_urls": []}})
    assert empty["urls"]["url_count"] == 0
    assert empty["discovery_status"] == "observed"
    invalid = build_email_url_evidence({"content": {"extracted_urls": ["javascript:alert(1)", "https://user:secret@example.test/"]}})
    assert invalid["invalid_url_count"] == 2
    assert invalid["urls"]["https"] is None
    assert invalid["urls"]["domain_age_days"] is None


def test_punycode_is_recorded_as_syntax_not_proven_brand_impersonation():
    evidence = build_email_url_evidence({"content": {"extracted_urls": ["https://xn--bcher-kva.de/"]}})
    assert evidence["urls"]["homoglyph"] is True
    assert evidence["punycode_semantics"] == "syntax_only_not_confirmed_brand_impersonation"
    assert evidence["urls"]["typosquatting"] is None
