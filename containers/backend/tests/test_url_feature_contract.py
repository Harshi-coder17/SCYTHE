from pathlib import Path
import json
from types import SimpleNamespace

from services.model_features import url_features
from services.model_features.url_features import FEATURE_NAMES, build_url_feature_vector

def test_runtime_url_features_match_training_contract():
    # Frozen independent training outputs are checked in so Linux CI and a
    # standalone repository do not import Windows research binary dependencies.
    fixture = json.loads((Path(__file__).parent / "fixtures/url_feature_contract_v1.json").read_text(encoding="utf-8"))
    assert fixture["version"] == "training_url_feature_golden_v1"
    assert len(fixture["source_sha256"]) == 64
    assert FEATURE_NAMES == tuple(fixture["feature_names"])
    for case in fixture["cases"]:
        result = build_url_feature_vector(case["raw"])
        assert result["status"] == "observed"
        assert result["canonical_url"] == case["canonical_url"]
        assert result["values"] == case["values"]


def test_invalid_urls_fail_closed_without_safe_looking_vector():
    for raw in ("", "ftp://example.com/file", "https://user:secret@example.com/", "x" * 8193, None):
        result = build_url_feature_vector(raw)
        assert result["status"] == "unavailable"
        assert result["values"] is None
        assert result["reason"] == "invalid_http_url"


def test_ipv6_literals_remain_valid_and_keep_ip_features():
    result = build_url_feature_vector("https://[2001:db8::1]:8443/path")
    assert result["status"] == "observed"
    assert result["canonical_url"] == "https://[2001:db8::1]:8443/path"
    assert result["values"][3] == 1
    assert result["values"][14] == 1


def test_backend_pinned_tldextract_api_is_supported(monkeypatch):
    # tldextract 5.1.2, pinned by the backend image, predates the renamed
    # top_domain_under_public_suffix property.
    monkeypatch.setattr(url_features, "_extractor", lambda _host: SimpleNamespace(
        registered_domain="bit.ly", subdomain="www"))
    result = build_url_feature_vector("https://www.bit.ly/path")
    assert result["status"] == "observed"
    assert result["values"][13] == 1
