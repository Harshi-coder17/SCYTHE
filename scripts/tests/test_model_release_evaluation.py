"""Release gates use synthetic evidence only; no untouched model is scored here."""
import importlib.util
import json
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location("model_release_evaluation", Path(__file__).resolve().parents[1] / "model_release_evaluation.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def write(path, value, jsonl=False):
    path.write_text("\n".join(json.dumps(row) for row in value) if jsonl else json.dumps(value), encoding="utf-8")
    return {"path": path.name, "sha256": release.sha256(path)}


@pytest.fixture
def registered(tmp_path, monkeypatch):
    # Fixtures deliberately have no internet/domain discovery dependencies.
    monkeypatch.setattr(release, "domain_from_canonical", lambda url: url.split("/")[2])
    policy = json.loads((Path(__file__).resolve().parents[2] / "docs/local_operational_model_policy_v1.json").read_text())
    policy["approved_at_utc"] = "2026-10-01T00:00:00Z"
    bindings = {"policy": write(tmp_path / "policy.json", policy),
                "model": write(tmp_path / "model.txt", "synthetic test classifier"),
                "feature_contract": write(tmp_path / "contract.json", {"version": "fixture_v1"}),
                "thresholds": write(tmp_path / "thresholds.json", {"safe": .1, "low": .3, "medium": .5, "high": .9}),
                "source_code": write(tmp_path / "code.txt", "synthetic scorer"),
                "protocol": write(tmp_path / "protocol.json", {"version": "fixture"})}
    provenance = write(tmp_path / "exclusion_source.json", {"version": "fixture"})
    bindings["excluded_groups"] = write(tmp_path / "exclusions.json", {"registrable_domains": ["examined.test"], "canonical_urls": [], "campaign_groups": ["known-campaign"], "visual_groups": ["known-visual"], "source_manifests": [provenance]})
    evidence_file = write(tmp_path / "publisher_evidence.json", {"description": "synthetic evidence for tests, never release data"})
    rows, evidence = [], []
    for index in range(7000):
        url = f"https://sample{index}.test/"
        row = {"sample_id": str(index), "label": int(index >= 5000), "canonical_url": url, "registrable_domain": f"sample{index}.test", "captured_at_utc": "2026-10-01T00:00:00Z", "source": "fixture"}
        rows.append(row)
        evidence.append({**row, "independent": True, "basis": "independent_historical_analysis", "observed_at_utc": "2026-10-01T01:00:00Z", "evidence": evidence_file})
    bindings["cohort"] = write(tmp_path / "cohort.jsonl", rows, True)
    bindings["independent_evidence"] = write(tmp_path / "evidence.jsonl", evidence, True)
    registration = {"schema_version": "scythe_release_registration_v2", "status": "untouched_external_holdout", "registered_at_utc": "2026-10-02T00:00:00Z", "operator": "fixture", "independent_evidence_reviewed_by": "fixture", "operator_attested_model_metrics_uninspected": True, "labels_independently_supported": True, "all_existing_and_examined_groups_in_exclusions": True, "model_version": "fixture", "feature_contract_version": "fixture_v1", "supported_paths": ["quick_url"], "bindings": bindings}
    path = tmp_path / "registration.json"
    write(path, registration)
    predictions = {"metadata": {"model_sha256": bindings["model"]["sha256"], "feature_contract_sha256": bindings["feature_contract"]["sha256"], "thresholds_sha256": bindings["thresholds"]["sha256"], "source_code_sha256": bindings["source_code"]["sha256"], "holdout_sha256": bindings["cohort"]["sha256"], "registration_sha256": release.sha256(path), "started_at_utc": "2026-10-03T00:00:00Z", "warm_latency_includes_preprocessing_validation_inference": True, "target_hardware": "synthetic"},
                   "records": [{"sample_id": row["sample_id"], "path": "quick_url", "status": "available", "probability": .9 if row["label"] else .1, "elapsed_ms": 100} for row in rows]}
    predictions_path = tmp_path / "predictions.json"
    write(predictions_path, predictions)
    return path, predictions_path, registration, predictions


def test_qualified_perfect_fixture_passes_and_binds_artifacts(registered):
    path, predictions, _, _ = registered
    report = release.evaluate(path, predictions)
    assert report["verified"] and report["passed"], report["blockers"]
    assert report["model_sha256"]
    metrics = report["quality_by_path"]["quick_url"]
    assert metrics["recall_wilson95"][0] > .8
    assert metrics["false_positive_rate_wilson95"][1] < .01
    assert metrics["roc_auc"] == metrics["pr_auc_average_precision"] == 1


def test_v2_evaluation_binds_both_path_models_and_uses_frozen_thresholds(registered):
    path, predictions_path, registration, predictions = registered
    root = path.parent
    models = {}
    fusion = {}
    for score_path in ("quick_url", "deep_url"):
        model_file = root / f"{score_path}.txt"
        model_file.write_text("synthetic candidate model")
        binding = {"path": model_file.name, "sha256": release.sha256(model_file)}
        models[score_path] = binding
        fusion[score_path] = {"model_version": "scythe_fusion_v2",
            "feature_contract_version": "scythe_fusion_v2", "artifact_file": model_file.name,
            "artifact_sha256": binding["sha256"], "threshold": .6}
    registration["feature_contract_version"] = "scythe_fusion_v2"
    registration["model_version"] = "fixture_fusion_v2"
    registration["supported_paths"] = ["quick_url", "deep_url"]
    contract = {"version": "scythe_fusion_v2", "fusion_by_path": fusion}
    registration["bindings"].pop("model")
    registration["bindings"]["models_by_path"] = write(root / "models_by_path.json", models)
    registration["bindings"]["feature_contract"] = write(root / "contract.json", contract)
    registration["bindings"]["thresholds"] = write(root / "thresholds.json", {
        "deployment_threshold": True, "decision_thresholds": {"quick_url": .6, "deep_url": .6}})
    cohort_path = root / registration["bindings"]["cohort"]["path"]
    rows = release.read_jsonl(cohort_path)
    image_file = root / "fixture.png"
    image_file.write_bytes(b"fixture image reference")
    image_ref = {"path": image_file.name, "sha256": release.sha256(image_file)}
    for row in rows:
        row["image"] = image_ref
    registration["bindings"]["cohort"] = write(cohort_path, rows, True)
    write(path, registration)
    records = []
    for score_path in registration["supported_paths"]:
        records.extend({"sample_id": row["sample_id"], "path": score_path, "status": "available",
                        "probability": .9 if row["label"] else .1, "elapsed_ms": 100}
                       for row in rows)
    predictions["metadata"].pop("model_sha256")
    predictions["metadata"]["model_sha256_by_path"] = {
        key: value["sha256"] for key, value in models.items()}
    predictions["metadata"]["feature_contract_sha256"] = registration["bindings"]["feature_contract"]["sha256"]
    predictions["metadata"]["thresholds_sha256"] = registration["bindings"]["thresholds"]["sha256"]
    predictions["metadata"]["holdout_sha256"] = registration["bindings"]["cohort"]["sha256"]
    predictions["metadata"]["registration_sha256"] = release.sha256(path)
    predictions["records"] = records
    write(predictions_path, predictions)
    report = release.evaluate(path, predictions_path)
    assert report["verified"] and report["passed"], report["blockers"]
    assert report["model_sha256_by_path"] == {key: value["sha256"] for key, value in models.items()}


def test_unqualified_preflight_never_opens_predictions(tmp_path):
    path = tmp_path / "registration.json"
    write(path, {"status": "development_benchmark"})
    result = release.evaluate(path, tmp_path / "must-not-open.json")
    assert not result["verified"]
    assert "holdout is not registered untouched" in result["blockers"]


@pytest.mark.parametrize("mutation", ["wrong_hash", "wrong_membership", "unavailable", "nan_probability", "timeout", "low_recall", "false_positives", "wrong_binding"])
def test_invalid_or_failed_evaluations_do_not_pass(registered, mutation):
    path, prediction_path, registration, predictions = registered
    if mutation == "wrong_hash":
        (path.parent / "model.txt").write_text("changed")
    elif mutation == "wrong_membership":
        predictions["records"][0]["sample_id"] = "out-of-cohort"
    elif mutation == "unavailable":
        predictions["records"][5000].update(status="unavailable", probability=None)
    elif mutation == "nan_probability":
        predictions["records"][0]["probability"] = float("nan")
    elif mutation == "timeout":
        predictions["records"][0]["elapsed_ms"] = 60001
    elif mutation == "low_recall":
        for row in predictions["records"][5000:5400]:
            row["probability"] = .1  # exactly .80 recall still fails confidence bound
    elif mutation == "false_positives":
        for row in predictions["records"][:50]:
            row["probability"] = .9  # exactly 1% FPR still fails confidence bound
    elif mutation == "wrong_binding":
        predictions["metadata"]["model_sha256"] = "0" * 64
    write(prediction_path, predictions)
    assert not release.evaluate(path, prediction_path)["passed"]


@pytest.mark.parametrize("mutation", ["domain", "label", "evidence_hash", "late_evidence", "campaign", "visual"])
def test_overlap_and_unsupported_evidence_fail_preflight(registered, mutation):
    path, prediction_path, registration, _ = registered
    name = "cohort" if mutation in {"domain", "campaign", "visual"} else "independent_evidence"
    target = path.parent / registration["bindings"][name]["path"]
    rows = release.read_jsonl(target)
    if mutation == "domain":
        rows[0]["registrable_domain"] = "examined.test"
    elif mutation == "campaign":
        rows[0]["campaign_group"] = "known-campaign"
    elif mutation == "visual":
        rows[0]["visual_group"] = "known-visual"
    elif mutation == "label":
        rows[0]["label"] = 1
    elif mutation == "evidence_hash":
        rows[0]["evidence"]["sha256"] = "0" * 64
    elif mutation == "late_evidence":
        rows[0]["observed_at_utc"] = "2026-10-04T00:00:00Z"
    registration["bindings"][name] = write(target, rows, True)
    write(path, registration)
    assert not release.evaluate(path, prediction_path)["verified"]


def test_ranking_metrics_ties_and_single_class():
    metrics = release.ranking_metrics([(.5, 0), (.5, 1)])
    assert metrics["roc_auc"] == .5
    assert metrics["pr_auc_average_precision"] == .5
    assert release.ranking_metrics([(.2, 0)])["roc_auc"] is None
    assert release.wilson(0, 0) == [None, None]


def test_cli_refuses_existing_output_before_evaluating(tmp_path, monkeypatch):
    output = tmp_path / "already-finalized"
    output.mkdir()
    monkeypatch.setattr("sys.argv", ["model_release_evaluation", "--registration", "unused.json", "--output-dir", str(output)])
    with pytest.raises(FileExistsError):
        release.main()


def test_export_evidence_creates_exact_verified_bundle(registered, tmp_path):
    path, predictions_path, _, _ = registered
    report = release.evaluate(path, predictions_path)
    assert report["verified"] and report["passed"]

    out_dir = tmp_path / "exported_bundle"
    evidence_map = release.export_evidence(path, predictions_path, out_dir, report)
    ev_root = out_dir / "evidence"
    assert ev_root.is_dir()
    for name in ("registration.json", "holdout.jsonl", "independent_evidence.jsonl",
                 "predictions.json", "exclusions.json", "source_code.tar.gz", "protocol.json"):
        fpath = ev_root / name
        assert fpath.is_file()
        assert release.sha256(fpath) == report[name.split(".")[0] + "_sha256"]


def test_export_evidence_refuses_unverified_report(registered, tmp_path):
    path, predictions_path, _, _ = registered
    unverified_report = {"verified": False}
    with pytest.raises(ValueError, match="cannot export unverified evidence"):
        release.export_evidence(path, predictions_path, tmp_path / "bad_export", unverified_report)

