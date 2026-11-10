"""Regression cases for evidence bypasses; synthetic test records only."""
import importlib.util
import json
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("release_integrity", Path(__file__).resolve().parents[2] / "containers/backend/services/model_release.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def inputs(tmp_path):
    holdout = tmp_path / "holdout.jsonl"
    holdout.write_text(json.dumps(dict(sample_id="one", label=1, registrable_domain="example.com")))
    predictions = tmp_path / "predictions.json"
    row = dict(sample_id="one", path="quick_url", status="available", probability=.9, elapsed_ms=10)
    predictions.write_text(json.dumps(dict(records=[row])))
    return holdout, predictions, row


def test_valid_record_uses_frozen_threshold(tmp_path):
    h, p, _ = inputs(tmp_path)
    assert module._recompute_qualification_records(h, p, ["quick_url"], {"quick_url": .95})["quick_url"]["fn"] == 1


@pytest.mark.parametrize("mutation", ["duplicate", "unknown", "missing", "threshold", "nan", "timeout"])
def test_invalid_prediction_records_rejected(tmp_path, mutation):
    h, p, row = inputs(tmp_path)
    records = [row]
    if mutation == "duplicate": records.append(row.copy())
    if mutation == "unknown": row["sample_id"] = "other"
    if mutation == "missing": records = []
    if mutation == "threshold": row["threshold"] = .1
    if mutation == "nan": row["probability"] = float("nan")
    if mutation == "timeout": row["elapsed_ms"] = 60001
    p.write_text(json.dumps(dict(records=records)))
    with pytest.raises(module.ReleaseUnavailable):
        module._recompute_qualification_records(h, p, ["quick_url"], {"quick_url": .5})


def test_empty_evidence_map_cannot_bypass_physical_checks(tmp_path):
    import hashlib
    keys = ("registration", "holdout", "independent_evidence", "predictions", "exclusions", "source_code", "protocol")
    evaluation = {key + "_sha256": hashlib.sha256(key.encode()).hexdigest() for key in keys}
    evaluation["evidence_files"] = {}
    policy = dict(minimum_phishing_records=2000, minimum_benign_records=5000, require_wilson95_bounds=True, minimum_coverage=1)
    with pytest.raises(module.ReleaseUnavailable, match="evidence_manifest_mismatch"):
        module.validate_qualification_summary(evaluation, policy, ["quick_url"], tmp_path)


def _write_blob(root, value):
    import hashlib
    import json
    data = json.dumps(value, sort_keys=True).encode()
    digest = hashlib.sha256(data).hexdigest()
    path = root / "evidence" / "blobs" / digest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return digest


def test_tranco_rank_and_http_success_are_not_benign_evidence(tmp_path):
    row = dict(sample_id="site-1", canonical_url="https://example.com/", label=0,
               captured_at_utc="2026-10-20T00:00:00Z")
    digest = _write_blob(tmp_path, {**row, "authority": "Tranco Official Top 1M Research Ranking",
                                   "http_status": 200})
    proof = {"evidence": {"sha256": digest}}
    with pytest.raises(module.ReleaseUnavailable, match="independent_corroboration_missing"):
        module._verify_sample_label_evidence(tmp_path, row, proof)


def test_exact_sample_independent_owner_evidence_is_accepted(tmp_path):
    row = dict(sample_id="site-1", canonical_url="https://example.com/", label=0,
               captured_at_utc="2026-10-20T00:00:00Z")
    corroboration = {**row, "independent": True, "source": "owner DNS challenge",
                     "basis": "documented_site_owner_control"}
    corroboration_hash = _write_blob(tmp_path, corroboration)
    primary = {**row, "authority": "capture metadata", "independent_corroboration": {
        "source": corroboration["source"], "sha256": corroboration_hash}}
    primary_hash = _write_blob(tmp_path, primary)
    module._verify_sample_label_evidence(tmp_path, row, {"evidence": {"sha256": primary_hash}})


def test_phishing_feed_membership_needs_distinct_corroboration(tmp_path):
    row = dict(sample_id="phish-1", canonical_url="https://example.net/login", label=1,
               captured_at_utc="2026-10-20T00:00:00Z")
    digest = _write_blob(tmp_path, {**row, "publisher_threat_feed": "Feed A",
                                   "independent_corroboration": {"source": "Feed A", "sha256": "1" * 64}})
    with pytest.raises(module.ReleaseUnavailable, match="independent_corroboration_invalid"):
        module._verify_sample_label_evidence(tmp_path, row, {"evidence": {"sha256": digest}})
