"""Safety tests for the opt-in, artifact-only shadow scoring task."""
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

import tasks.shadow_model_scoring as shadow


def _write_bundle(path: Path) -> str:
    path.mkdir()
    payload = path / "classifier.joblib"
    payload.write_bytes(b"trusted test bytes")
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    (path / "checksums.sha256").write_text(f"{digest}  classifier.joblib\n", encoding="ascii")
    return hashlib.sha256((path / "checksums.sha256").read_bytes()).hexdigest()


def test_bundle_requires_separate_manifest_trust_anchor(tmp_path):
    bundle = tmp_path / "bundle"
    trusted_hash = _write_bundle(bundle)

    resolved, entries = shadow._verify_bundle(str(bundle), trusted_hash, {"classifier.joblib"})

    assert resolved == bundle.resolve()
    assert entries["classifier.joblib"] == hashlib.sha256(b"trusted test bytes").hexdigest()
    with pytest.raises(ValueError, match="checksum_mismatch"):
        shadow._verify_bundle(str(bundle), "0" * 64, {"classifier.joblib"})


def test_bundle_verifies_nested_entries_and_rejects_traversal(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    nested = bundle / "candidate_models" / "baseline.joblib"
    nested.parent.mkdir()
    nested.write_bytes(b"candidate")
    checksum_path = bundle / "checksums.sha256"
    checksum_path.write_text(
        f"{hashlib.sha256(nested.read_bytes()).hexdigest()}  candidate_models/baseline.joblib\n",
        encoding="ascii",
    )
    trust_anchor = hashlib.sha256(checksum_path.read_bytes()).hexdigest()

    resolved, entries = shadow._verify_bundle(
        str(bundle), trust_anchor, {"candidate_models/baseline.joblib"}
    )

    assert resolved == bundle.resolve()
    assert "candidate_models/baseline.joblib" in entries

    checksum_path.write_text(f"{'0' * 64}  ../outside.joblib\n", encoding="ascii")
    traversal_trust_anchor = hashlib.sha256(checksum_path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="contract_mismatch"):
        shadow._verify_bundle(str(bundle), traversal_trust_anchor, {"../outside.joblib"})


def test_invalid_model_contract_fails_closed_before_deserialization(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    files = {
        "classifier.joblib": b"must not be deserialized",
        "feature_contract.json": json.dumps({"model_version": "unexpected"}).encode(),
        "threshold.json": b"{}",
        "run_manifest.json": json.dumps({"model_version": "lightgbm_dev_v2"}).encode(),
    }
    for name, content in files.items():
        (bundle / name).write_bytes(content)
    checksum_lines = [
        f"{hashlib.sha256(content).hexdigest()}  {name}"
        for name, content in sorted(files.items())
    ]
    manifest = bundle / "checksums.sha256"
    manifest.write_text("\n".join(checksum_lines) + "\n", encoding="ascii")
    with patch.object(shadow.settings, "SHADOW_LIGHTGBM_BUNDLE_DIR", str(bundle)), \
            patch.object(shadow.settings, "SHADOW_LIGHTGBM_CHECKSUMS_SHA256", hashlib.sha256(manifest.read_bytes()).hexdigest()):
        result = shadow._score_url("https://example.com/")

    assert result["status"] == "unavailable"
    assert result["phishing_probability"] is None
    assert result["error_reason"] == "contract_mismatch"


def test_native_lightgbm_bundle_scores_without_sklearn_pickle(tmp_path):
    import lightgbm
    import numpy as np

    bundle = tmp_path / "native_bundle"
    bundle.mkdir()
    x = np.asarray([[float(i + j) for j in range(15)] for i in range(8)], dtype=np.float64)
    y = np.asarray([0, 0, 0, 0, 1, 1, 1, 1], dtype=np.int32)
    booster = lightgbm.train(
        {"objective": "binary", "verbosity": -1, "num_leaves": 3,
         "min_data_in_leaf": 1, "num_threads": 1, "seed": 42},
        lightgbm.Dataset(x, label=y), num_boost_round=3,
    )
    booster.save_model(str(bundle / "classifier.txt"))
    feature_names = [
        "url_length", "host_length", "is_https", "is_ip_host", "subdomain_count",
        "hyphen_count", "digit_count", "special_count", "at_symbol",
        "question_mark_count", "path_length", "query_length", "has_punycode",
        "url_shortener_used", "is_bogon_space",
    ]
    (bundle / "feature_contract.json").write_text(json.dumps({
        "model_version": "lightgbm_dev_v2", "positive_label": 1,
        "features": feature_names, "status": "experimental_only",
        "scoring_backend": "lightgbm_native_booster",
    }), encoding="utf-8")
    (bundle / "threshold.json").write_text("{}", encoding="utf-8")
    (bundle / "run_manifest.json").write_text(json.dumps({
        "model_version": "lightgbm_dev_v2",
    }), encoding="utf-8")
    files = [p for p in bundle.iterdir() if p.is_file()]
    manifest = bundle / "checksums.sha256"
    manifest.write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
        for p in sorted(files)
    ), encoding="ascii")
    trusted_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
    values = x[0].tolist()
    with patch.object(shadow.settings, "SHADOW_LIGHTGBM_BUNDLE_DIR", str(bundle)), \
            patch.object(shadow.settings, "SHADOW_LIGHTGBM_CHECKSUMS_SHA256", trusted_hash), \
            patch.object(shadow, "build_url_feature_vector", return_value={
                "status": "observed", "values": values,
            }):
        result = shadow._score_url("https://example.com/")

    assert result["status"] == "observed"
    assert result["artifact_hashes"]["classifier_format"] == "lightgbm_native_text"
    assert result["phishing_probability"] == pytest.approx(float(booster.predict(x[:1])[0]))


def test_invalid_url_and_missing_image_return_unavailable_without_loading_models(tmp_path):
    invalid_url = shadow._score_url("file:///etc/passwd")
    missing_image = shadow._score_visual(tmp_path / "missing.png")

    assert invalid_url["status"] == "unavailable"
    assert invalid_url["phishing_probability"] is None
    assert invalid_url["error_reason"] == "invalid_http_url"
    assert missing_image["status"] == "unavailable"
    assert missing_image["phishing_probability"] is None
    assert missing_image["error_reason"] == "missing_screenshot"


def test_shadow_report_is_local_experimental_artifact(tmp_path):
    scan_id = "12345678-1234-4234-a234-123456789012"
    models = {
        "url": shadow._unavailable("lightgbm_dev_v2", "invalid_http_url"),
        "visual": shadow._unavailable("mobileclip_v2", "missing_screenshot"),
    }

    report = shadow._write_report(tmp_path, scan_id, models, shadow.time.monotonic())
    saved = json.loads((tmp_path / "shadow_model_report.json").read_text(encoding="utf-8"))

    assert report == saved
    assert saved["status"] == "unavailable"
    assert saved["experimental"] is True
    assert saved["automatic_incident_signal"] is False
    assert "risk_score" not in saved
    assert "severity" not in saved


def test_disabled_shadow_task_only_writes_unavailable_local_report(tmp_path):
    scan_id = "12345678-1234-4234-a234-123456789012"
    (tmp_path / scan_id).mkdir()
    with patch.object(shadow.settings, "SHARED_DIR", str(tmp_path)), \
            patch.object(shadow.settings, "SHADOW_SCORING_ENABLED", False):
        result = shadow.shadow_model_scoring_task(scan_id)

    assert result["status"] == "unavailable"
    assert result["models"]["url"]["error_reason"] == "disabled"
    assert (tmp_path / scan_id / "shadow_model_report.json").is_file()


def test_duplicate_task_reuses_saved_result_without_rescoring(tmp_path):
    scan_id = "12345678-1234-4234-a234-123456789012"
    observed = {
        "model_version": "lightgbm_dev_v2", "contract_version": "lightgbm_dev_v2",
        "status": "observed", "phishing_probability": 0.25,
        "artifact_hashes": {}, "error_reason": None,
    }
    with patch.object(shadow.settings, "SHARED_DIR", str(tmp_path)), \
            patch.object(shadow.settings, "SHADOW_SCORING_ENABLED", True), \
            patch.object(shadow, "_get_scan_url", return_value="https://example.com/"), \
            patch.object(shadow._REDIS, "set", side_effect=[True, False]), \
            patch.object(shadow, "_score_url", return_value=observed) as score_url:
        first = shadow.shadow_model_scoring_task(scan_id)
        second = shadow.shadow_model_scoring_task(scan_id)

    assert first["status"] == "observed"
    assert second == first
    score_url.assert_called_once_with("https://example.com/")


def test_duplicate_task_does_not_reuse_report_for_different_input(tmp_path):
    scan_id = "12345678-1234-4234-a234-123456789012"
    observed = {
        "model_version": "lightgbm_dev_v2", "contract_version": "lightgbm_dev_v2",
        "status": "observed", "phishing_probability": 0.25,
        "artifact_hashes": {}, "error_reason": None,
    }
    with patch.object(shadow.settings, "SHARED_DIR", str(tmp_path)), \
            patch.object(shadow.settings, "SHADOW_SCORING_ENABLED", True), \
            patch.object(shadow, "_get_scan_url", return_value="https://example.com/"), \
            patch.object(shadow._REDIS, "set", side_effect=[True, False]), \
            patch.object(shadow, "_score_url", return_value=observed):
        shadow.shadow_model_scoring_task(scan_id)
        report_path = tmp_path / scan_id / "shadow_model_report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["input_key_sha256"] = "stale-input-key"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        duplicate = shadow.shadow_model_scoring_task(scan_id)

    assert duplicate["status"] == "unavailable"
    assert duplicate["models"]["url"]["error_reason"] == "duplicate_task"
    assert duplicate["models"]["visual"]["error_reason"] == "duplicate_task"


def test_soft_timeout_persists_unavailable_report(tmp_path):
    from celery.exceptions import SoftTimeLimitExceeded

    scan_id = "12345678-1234-4234-a234-123456789012"
    with patch.object(shadow.settings, "SHARED_DIR", str(tmp_path)), \
            patch.object(shadow.settings, "SHADOW_SCORING_ENABLED", True), \
            patch.object(shadow, "_get_scan_url", return_value="https://example.com/"), \
            patch.object(shadow._REDIS, "set", return_value=True), \
            patch.object(shadow, "_score_url", side_effect=SoftTimeLimitExceeded()):
        result = shadow.shadow_model_scoring_task(scan_id)

    assert result["status"] == "unavailable"
    assert result["models"]["url"]["error_reason"] == "timeout"
    saved = json.loads((tmp_path / scan_id / "shadow_model_report.json").read_text(encoding="utf-8"))
    assert saved["models"]["visual"]["error_reason"] == "timeout"


def test_worker_failure_persists_unavailable_report(tmp_path):
    scan_id = "12345678-1234-4234-a234-123456789012"
    with patch.object(shadow.settings, "SHARED_DIR", str(tmp_path)), \
            patch.object(shadow.settings, "SHADOW_SCORING_ENABLED", True), \
            patch.object(shadow, "_get_scan_url", side_effect=RuntimeError("backend fixture failure")):
        result = shadow.shadow_model_scoring_task(scan_id)

    assert result["status"] == "unavailable"
    assert result["models"]["url"]["error_reason"] == "worker_failure"
    assert result["models"]["visual"]["error_reason"] == "worker_failure"
    assert (tmp_path / scan_id / "shadow_model_report.json").is_file()
