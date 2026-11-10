"""Research scorer tests never inspect an actual holdout or activate a release."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import time

import pytest

SPEC = importlib.util.spec_from_file_location("score_release_candidate", Path(__file__).resolve().parents[1] / "score_release_candidate.py")
scorer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scorer)


def simulated_worker(connection, config):
    connection.send({"ready": True})
    while True:
        request = connection.recv()
        if request["row"].get("slow"):
            time.sleep(2)
        if request["row"].get("crash"):
            os._exit(3)
        connection.send({"status": "available", "probability": .7})


def test_real_process_timeout_and_worker_failure_are_unavailable():
    isolated = scorer.IsolatedScorer({}, target=simulated_worker, timeout_seconds=5)
    try:
        isolated.start()
        isolated.timeout = .05
        result = isolated.score({"slow": True}, "quick_url", ".")
        assert result["status"] == "unavailable" and result["probability"] is None
        assert result["error_reason"] == "timeout"
        assert isolated.process is None
        isolated.timeout = 5
        isolated.start()
        result = isolated.score({"crash": True}, "quick_url", ".")
        assert result["error_reason"] == "worker_failure"
        assert isolated.process is None
    finally:
        isolated.close()


def test_current_style_development_registration_stops_before_worker_or_output(tmp_path):
    registration = tmp_path / "registration.json"
    registration.write_text(json.dumps({"status": "development_benchmark"}))
    class MustNotStart:
        def __init__(self, _):
            pytest.fail("unqualified data reached model worker")
    output = tmp_path / "predictions"
    with pytest.raises(ValueError, match="preflight failed"):
        scorer.score_candidate(registration, tmp_path, "0" * 64, tmp_path, output, scorer_factory=MustNotStart)
    assert not output.exists()


@pytest.fixture
def frozen_candidate(tmp_path, monkeypatch):
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "classifier.txt").write_text("synthetic classifier")
    contract = {"version": "fixture_v1", "positive_label": 1, "scoring_backend": "lightgbm_native_booster", "components_by_path": {"quick_url": {"url": {"fixture": "descriptor"}}}}
    (candidate / "feature_contract.json").write_text(json.dumps(contract))
    manifest = candidate / "checksums.sha256"
    manifest.write_text("".join(f"{scorer.evaluation.sha256(path)}  {path.name}\n" for path in sorted(candidate.iterdir()) if path != manifest))
    runtime_pins = {name: scorer.evaluation.sha256(scorer.BACKEND / name) for name in scorer.SHARED_SOURCES}
    registration = {"bindings": {"model": {"sha256": scorer.evaluation.sha256(candidate / "classifier.txt")}, "feature_contract": {"sha256": scorer.evaluation.sha256(candidate / "feature_contract.json")}, "source_code": {"sha256": scorer.evaluation.sha256(scorer.__file__)}}, "runtime_source_sha256": runtime_pins, "feature_contract_version": "fixture_v1", "supported_paths": ["quick_url"]}
    checked = {"verified": True, "registration": registration}
    monkeypatch.setattr(scorer.evaluation, "validate_registration", lambda _: checked)
    return candidate, scorer.evaluation.sha256(manifest), checked


def test_registered_candidate_hashes_and_runtime_sources_must_match(frozen_candidate):
    candidate, anchor, checked = frozen_candidate
    assert scorer.candidate_preflight("fixture", candidate, anchor)[0]["verified"]
    checked["registration"]["bindings"]["model"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="registered model"):
        scorer.candidate_preflight("fixture", candidate, anchor)


def test_changed_runtime_source_or_scorer_cannot_use_frozen_registration(frozen_candidate):
    candidate, anchor, checked = frozen_candidate
    checked["registration"]["runtime_source_sha256"][scorer.SHARED_SOURCES[0]] = "0" * 64
    with pytest.raises(ValueError, match="runtime source changed"):
        scorer.candidate_preflight("fixture", candidate, anchor)


def test_training_warmup_cannot_contain_holdout_record(tmp_path):
    row = {"sample_id": "holdout", "canonical_url": "https://held.test/", "registrable_domain": "held.test"}
    record = tmp_path / "training.json"
    record.write_text(json.dumps(row))
    binding = tmp_path / "warmup.json"
    binding.write_text(json.dumps({"role": "training_warmup", "record": {"path": record.name, "sha256": scorer.evaluation.sha256(record)}}))
    with pytest.raises(ValueError, match="overlaps frozen holdout"):
        scorer.load_training_warmup(binding, [row], tmp_path)


def test_scoring_uses_shared_features_and_absent_required_data_is_unavailable(tmp_path):
    release_spec = importlib.util.spec_from_file_location("release_contract", scorer.BACKEND / "services/model_release.py")
    release = importlib.util.module_from_spec(release_spec)
    release_spec.loader.exec_module(release)
    obs_spec = importlib.util.spec_from_file_location("observation_shared", scorer.BACKEND / "services/model_features/scythe_observations.py")
    observations = importlib.util.module_from_spec(obs_spec)
    obs_spec.loader.exec_module(observations)
    signals_spec = importlib.util.spec_from_file_location("signals_shared", scorer.BACKEND / "services/model_features/fusion_signals.py")
    signals = importlib.util.module_from_spec(signals_spec)
    signals_spec.loader.exec_module(signals)
    contract = {"features": [{"name": "url_probability", "path": "components.url_probability", "type": "number", "nullable": False}, {"name": "forms", "path": "scan_signals.browser_dom_form_count", "type": "number", "nullable": False}], "components_by_path": {"quick_url": {"url": {"fixture": "descriptor"}}}}
    runtime = {"contract": contract, "root": tmp_path, "hashes": {}, "encoder_root": tmp_path,
               "checked": {"registration": {"registered_at_utc": "2026-10-02T00:00:00Z"}}, "release": release, "observations": observations, "signals": signals,
               "components": SimpleNamespace(score_components=lambda *_: {"url": {"status": "observed", "artifact_hashes": {"fixture": "descriptor"}, "phishing_probability": .8}}),
               "model": SimpleNamespace(predict=lambda *_args, **_kwargs: [.73])}
    row = {"sample_id": "fixture", "canonical_url": "https://fixture.test/", "captured_at_utc": "2026-10-01T00:00:00Z", "capture_id": "capture"}
    with pytest.raises(ValueError, match="missing_evidence"):
        scorer.score_one(runtime, row, "quick_url", tmp_path)
    evidence = tmp_path / "scan.json"
    evidence.write_text(json.dumps({"capture_id": "capture", "browser_features": {"dom": {"forms": 2}}}))
    row["scan_evidence"] = {"path": evidence.name, "sha256": scorer.evaluation.sha256(evidence)}
    assert scorer.score_one(runtime, row, "quick_url", tmp_path) == {"status": "available", "probability": .73}
    evidence.write_text("{}")
    with pytest.raises(ValueError, match="changed bound file"):
        scorer.score_one(runtime, row, "quick_url", tmp_path)


@pytest.mark.parametrize("with_warmup", [False, True])
def test_exact_membership_and_truthful_warm_latency_metadata(tmp_path, monkeypatch, with_warmup):
    source = tmp_path / "source"
    source.write_text("fixture")
    rows = [{"sample_id": "a"}, {"sample_id": "b"}]
    checked = {"registration": {"supported_paths": ["quick_url"], "runtime_source_sha256": {}}, "cohort": rows,
               "files": {key: source for key in ("model", "feature_contract", "thresholds", "cohort", "source_code")}}
    monkeypatch.setattr(scorer, "candidate_preflight", lambda *_: (checked, {}, {}))
    monkeypatch.setattr(scorer, "load_training_warmup", lambda *_: {"row": {"sample_id": "training"}, "base": str(tmp_path), "manifest_sha256": "fixture"} if with_warmup else None)
    class FakeScorer:
        def __init__(self, _):
            self.process = None
        def start(self):
            self.process = object()
        def score(self, *_):
            return {"status": "available", "probability": .7, "elapsed_ms": 1}
        def close(self):
            self.process = None
    target = scorer.score_candidate(source, tmp_path, "fixture", tmp_path, tmp_path / "predictions", scorer_factory=FakeScorer)
    result = json.loads(target.read_text())
    assert [row["sample_id"] for row in result["records"]] == ["a", "b"]
    assert result["metadata"]["warm_latency_includes_preprocessing_validation_inference"] is with_warmup
    assert all(row["latency_state"] == ("warm" if with_warmup else "cold_or_unverified") for row in result["records"])
    assert "risk_score" not in result["records"][0]
