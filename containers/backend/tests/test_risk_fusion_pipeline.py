"""
Unit tests for the legacy URL feature contract and release-gated model pipeline.
Verifies exact 15-feature contract matching schema.json, robust feature extraction,
strict missing-value handling and that only the verified worker can score.
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import risk_fusion
from risk_fusion import (
    FEATURE_COLUMNS,
    build_feature_vector,
    load_model,
    predict_probability,
    run_risk_fusion,
    RiskFusionEngine,
)


EXPECTED_15_FEATURES = [
    "url_length",
    "host_length",
    "is_https",
    "is_ip_host",
    "subdomain_count",
    "hyphen_count",
    "digit_count",
    "special_count",
    "at_symbol",
    "question_mark_count",
    "path_length",
    "query_length",
    "has_punycode",
    "url_shortener_used",
    "is_bogon_space",
]


def test_feature_columns_match_schema_json():
    schema_path = Path(__file__).resolve().parent.parent.parent.parent / "lightgbm_dataset" / "schema.json"
    if schema_path.is_file():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assert FEATURE_COLUMNS == schema["feature_matrix_columns"]
    assert FEATURE_COLUMNS == EXPECTED_15_FEATURES


def test_build_feature_vector_from_url():
    features = {name: 0 for name in FEATURE_COLUMNS}
    features.update(url="https://sub.example.com/login?token=abc", is_https=1, is_ip_host=0,
                    subdomain_count=1, is_bogon_space=0)
    vector = build_feature_vector(features)
    assert len(vector) == 15
    assert all(isinstance(v, (int, float)) for v in vector)
    # is_https should be 1.0
    assert vector[FEATURE_COLUMNS.index("is_https")] == 1.0
    # is_ip_host should be 0.0
    assert vector[FEATURE_COLUMNS.index("is_ip_host")] == 0.0
    # subdomain_count should be 1.0
    assert vector[FEATURE_COLUMNS.index("subdomain_count")] == 1.0
    # is_bogon_space should default to 0.0 for non-IP
    assert vector[FEATURE_COLUMNS.index("is_bogon_space")] == 0.0


def test_build_feature_vector_from_nested_browser_features_and_cyberintel():
    features = {name: 0 for name in FEATURE_COLUMNS}
    features.update(browser_features={"final_url": "http://192.168.1.1/admin"},
                    cyberintel={"is_bogon_space": 1}, is_ip_host=1, is_bogon_space=1)
    vector = build_feature_vector(features)
    assert len(vector) == 15
    assert vector[FEATURE_COLUMNS.index("is_https")] == 0.0
    assert vector[FEATURE_COLUMNS.index("is_ip_host")] == 1.0
    assert vector[FEATURE_COLUMNS.index("is_bogon_space")] == 1.0


def test_build_feature_vector_with_direct_feature_overrides():
    features = {name: 0 for name in FEATURE_COLUMNS}
    features.update(url="https://example.com/", url_length=42.0, is_https=0.0, is_bogon_space=1.0)
    vector = build_feature_vector(features)
    assert vector[FEATURE_COLUMNS.index("url_length")] == 42.0
    assert vector[FEATURE_COLUMNS.index("is_https")] == 0.0
    assert vector[FEATURE_COLUMNS.index("is_bogon_space")] == 1.0


def test_build_feature_vector_rejects_missing_and_invalid_values():
    with pytest.raises(ValueError, match="missing_features"):
        build_feature_vector({})
    with pytest.raises(ValueError, match="invalid_feature_input"):
        build_feature_vector(None)

    full = {name: 0 for name in FEATURE_COLUMNS}
    for invalid in (None, float("nan"), "not_a_number", True):
        row = {**full, "url_length": invalid}
        with pytest.raises(ValueError, match="invalid_feature_value"):
            build_feature_vector(row)


def test_build_feature_vector_requires_exact_list_length_and_finite_values():
    with pytest.raises(ValueError, match="invalid_feature_count"):
        build_feature_vector([1.0, 2.0, 3.0])
    assert build_feature_vector([0.0] * 15) == [0.0] * 15
    with pytest.raises(ValueError, match="invalid_feature_value"):
        build_feature_vector([0.0] * 14 + [float("inf")])


def test_legacy_loader_never_loads_direct_models(monkeypatch):
    monkeypatch.setattr(risk_fusion, "model", None)
    loaded = load_model()
    assert loaded == "MODEL_NOT_AVAILABLE"
    assert risk_fusion.model == "MODEL_NOT_AVAILABLE"


def test_legacy_artifact_loader_rejects_every_format(tmp_path):
    for suffix in (".txt", ".joblib", ".pkl"):
        artifact = tmp_path / f"model{suffix}"
        artifact.write_bytes(b"model bytes")
        with pytest.raises(ValueError, match="unverified_model_loading_disabled"):
            risk_fusion._load_model_from_file(artifact)


def test_predict_probability_when_model_not_available(monkeypatch):
    monkeypatch.setattr(risk_fusion, "model", "MODEL_NOT_AVAILABLE")
    prob = predict_probability([0.0] * 15)
    assert prob is None


def test_predict_probability_with_booster(monkeypatch):
    mock_booster = MagicMock()
    mock_booster.predict.return_value = [0.725]
    del mock_booster.predict_proba  # ensure predict_proba is not present
    monkeypatch.setattr(risk_fusion, "model", mock_booster)

    prob = predict_probability([0.0] * 15)
    assert prob == pytest.approx(0.725)
    mock_booster.predict.assert_called_once()


def test_predict_probability_with_sklearn_classifier(monkeypatch):
    mock_clf = MagicMock()
    mock_clf.classes_ = [0, 1]
    mock_clf.predict_proba.return_value = [[0.2, 0.8]]
    monkeypatch.setattr(risk_fusion, "model", mock_clf)

    prob = predict_probability([0.0] * 15)
    assert prob == pytest.approx(0.8)
    mock_clf.predict_proba.assert_called_once()


def test_predict_probability_clamps_to_zero_one(monkeypatch):
    mock_booster = MagicMock()
    del mock_booster.predict_proba
    mock_booster.predict.return_value = [1.5]
    monkeypatch.setattr(risk_fusion, "model", mock_booster)
    assert predict_probability([0.0] * 15) == 1.0

    mock_booster.predict.return_value = [-0.5]
    assert predict_probability([0.0] * 15) == 0.0


def test_predict_probability_handles_exceptions_gracefully(monkeypatch):
    mock_booster = MagicMock()
    del mock_booster.predict_proba
    mock_booster.predict.side_effect = RuntimeError("Prediction explosion")
    monkeypatch.setattr(risk_fusion, "model", mock_booster)

    prob = predict_probability([0.0] * 15)
    assert prob is None


def test_predict_probability_rejects_incomplete_or_nonfinite_vectors(monkeypatch):
    mock_booster = MagicMock()
    del mock_booster.predict_proba
    monkeypatch.setattr(risk_fusion, "model", mock_booster)
    assert predict_probability([0.0, 1.0]) is None
    assert predict_probability([0.0] * 14 + [float("nan")]) is None
    mock_booster.predict.assert_not_called()


def test_run_risk_fusion_disabled_stays_unavailable_even_if_legacy_model_is_loaded(monkeypatch):
    monkeypatch.setattr(risk_fusion, "model", MagicMock())
    with patch("config.settings.MODEL_RELEASE_ENABLED", False):
        result = run_risk_fusion({"url": "https://example.com"})
    assert result["is_placeholder"] is True
    assert result["availability"] == "unavailable"
    assert result["error_reason"] == "release_not_configured"
    assert result["probability"] is None
    assert result["risk_score"] is None
    assert result["risk_level"] == "UNKNOWN"


def test_run_risk_fusion_only_accepts_verified_worker_result(monkeypatch):
    job = MagicMock()
    job.get.return_value = {"is_placeholder": False, "availability": "observed", "probability": .82,
                            "risk_score": 82, "risk_level": "HIGH", "model_version": "fixture-v1",
                            "contract_version": "fixture-contract-v1", "release_manifest_sha256": "a" * 64,
                            "model_sha256": "b" * 64}
    with patch("config.settings.MODEL_RELEASE_ENABLED", True), \
            patch("tasks.model_inference.model_inference_task.apply_async", return_value=job) as dispatch:
        result = run_risk_fusion({"url": "https://suspicious-site.xyz/login"})
    assert result["probability"] == pytest.approx(.82)
    assert dispatch.call_args.kwargs["queue"] == "models"


def test_run_risk_fusion_rejects_incomplete_or_invalid_worker_result():
    job = MagicMock()
    job.get.return_value = {"is_placeholder": False, "availability": "observed", "probability": .82,
                            "risk_score": 82, "risk_level": "HIGH"}
    with patch("config.settings.MODEL_RELEASE_ENABLED", True), \
            patch("tasks.model_inference.model_inference_task.apply_async", return_value=job):
        result = run_risk_fusion({"url": "https://example.org/"})
    assert result["is_placeholder"] is True and result["probability"] is None
    assert result["error_reason"] == "invalid_worker_result"


def test_run_risk_fusion_preserves_only_well_formed_unavailable_worker_results():
    job = MagicMock()
    job.get.return_value = {"is_placeholder": True, "availability": "unavailable",
        "automatic_decision": False, "risk_level": "UNKNOWN", "risk_score": None,
        "probability": None, "error_reason": "checksum_mismatch"}
    with patch("config.settings.MODEL_RELEASE_ENABLED", True), \
            patch("tasks.model_inference.model_inference_task.apply_async", return_value=job):
        good = run_risk_fusion({"url": "https://example.org"})
    assert good["risk_level"] == "UNKNOWN" and good["probability"] is None
    assert good["error_reason"] == "checksum_mismatch"

    job.get.return_value["risk_level"] = "SAFE"
    with patch("config.settings.MODEL_RELEASE_ENABLED", True), \
            patch("tasks.model_inference.model_inference_task.apply_async", return_value=job):
        malformed = run_risk_fusion({"url": "https://example.org"})
    assert malformed["risk_level"] == "UNKNOWN" and malformed["probability"] is None
    assert malformed["error_reason"] == "invalid_worker_result"


def test_run_risk_fusion_requires_threshold_for_v2_binary_worker_result():
    job = MagicMock()
    job.get.return_value = {"is_placeholder": False, "availability": "observed", "probability": .82,
        "risk_score": 82, "risk_level": "HIGH", "model_version": "fixture-v2",
        "contract_version": "scythe_fusion_v2", "release_manifest_sha256": "a" * 64,
        "model_sha256": "b" * 64}
    with patch("config.settings.MODEL_RELEASE_ENABLED", True), \
            patch("tasks.model_inference.model_inference_task.apply_async", return_value=job):
        result = run_risk_fusion({"url": "https://example.org"})
    assert result["risk_level"] == "UNKNOWN" and result["error_reason"] == "invalid_worker_result"


def test_run_risk_fusion_rejects_unverifiable_worker_artifact_identity():
    job = MagicMock()
    job.get.return_value = {"is_placeholder": False, "availability": "observed", "probability": .82,
        "risk_score": 82, "risk_level": "HIGH", "model_version": "fixture-v1",
        "contract_version": "fixture-contract-v1", "release_manifest_sha256": "unverified",
        "model_sha256": "b" * 64}
    with patch("config.settings.MODEL_RELEASE_ENABLED", True), \
            patch("tasks.model_inference.model_inference_task.apply_async", return_value=job):
        result = run_risk_fusion({"url": "https://example.org"})
    assert result["risk_level"] == "UNKNOWN" and result["error_reason"] == "invalid_worker_result"


def test_run_risk_fusion_rejects_missing_url_without_dispatch():
    with patch("config.settings.MODEL_RELEASE_ENABLED", True), \
            patch("tasks.model_inference.model_inference_task.apply_async") as dispatch:
        result = run_risk_fusion({})
    assert result["is_placeholder"] is True and result["probability"] is None
    dispatch.assert_not_called()


def test_risk_fusion_engine_compute_keeps_disabled_result_unknown():
    engine = RiskFusionEngine()
    report = engine.compute(
        cyberintel={"target": "https://safe.com", "iocs": []},
        browser_features={"url": "https://safe.com"},
        sandbox_features={},
        consistency_report={"cloaking_suspected": False},
    )
    assert report["is_placeholder"] is True
    assert report["risk_score"] is None
    assert report["severity"] == "UNKNOWN"
    assert "Validated model verdict unavailable" in " ".join(report["explanations"])
