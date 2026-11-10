import hashlib
import importlib.util
import json
from pathlib import Path
import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "model_release_readiness.py"
spec = importlib.util.spec_from_file_location("model_release_readiness", MODULE_PATH)
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


def test_workspace_rejects_repository_root_before_reporting_missing_models(tmp_path):
    for name in ("SCYTHE", "lightgbm_dataset", "mobileclip-dataset"):
        (tmp_path / name).mkdir()
    assert readiness.validate_workspace(tmp_path) == tmp_path.resolve()
    with pytest.raises(ValueError, match="parent containing SCYTHE"):
        readiness.validate_workspace(tmp_path / "SCYTHE")


def test_new_candidates_remain_experimental_and_superseded_versions_stay_visible(tmp_path):
    collection = tmp_path / "lightgbm_dataset/prospective_collection_v1"
    collection.mkdir(parents=True)
    (collection / "v1_conflict_census.json").write_text(json.dumps({
        "status": "superseded_experimental_candidate_do_not_promote"}))
    for name in ("url_candidate_v1", "url_candidate_v2"):
        target = collection / name
        target.mkdir()
        manifest = target / "run_manifest.json"
        manifest.write_text(json.dumps({"version": name, "status": "experimental_only"}))
        (target / "checksums.sha256").write_text(f"{readiness.sha256(manifest)}  run_manifest.json\n")
    url_artifacts = tmp_path / "lightgbm_dataset/fresh/artifacts/url_character_dev_v2"
    url_artifacts.mkdir(parents=True)
    url_manifest = url_artifacts / "run_manifest.json"
    url_manifest.write_text(json.dumps({"version": "url_character_dev_v2", "status": "experimental_only"}))
    (url_artifacts / "checksums.sha256").write_text(f"{readiness.sha256(url_manifest)}  run_manifest.json\n")
    fusion_artifact = tmp_path / "lightgbm_dataset/prospective_reviewed_dev_v2_fusion_v2"
    fusion_artifact.mkdir()
    fusion_manifest = fusion_artifact / "run_manifest.json"
    fusion_manifest.write_text(json.dumps({"status": "experimental_only", "release_approved": False}))
    (fusion_artifact / "checksums.sha256").write_text(f"{readiness.sha256(fusion_manifest)}  run_manifest.json\n")
    reports = readiness.inspect_additional_candidates(tmp_path)
    by_path = {item["path"]: item for item in reports}
    assert by_path["lightgbm_dataset/prospective_collection_v1/url_candidate_v1"]["status"] == "superseded_do_not_promote"
    assert by_path["lightgbm_dataset/prospective_collection_v1/url_candidate_v1"]["supersession_evidence_sha256"]
    assert by_path["lightgbm_dataset/prospective_collection_v1/url_candidate_v2"]["status"] == "experimental_only"
    assert by_path["lightgbm_dataset/fresh/artifacts/url_character_dev_v2"]["status"] == "experimental_only"
    assert by_path["lightgbm_dataset/prospective_reviewed_dev_v2_fusion_v2"]["status"] == "experimental_only"
    assert all(item["hashes"]["valid"] and item["release_approved"] is False for item in reports)


def test_file_size_and_health_alone_cannot_certify_missing_artifacts(tmp_path):
    report = readiness.build_report(tmp_path)
    assert report["production_ready"] is False
    assert report["research_artifacts_verified"] is False
    assert any("untouched" in reason for reason in report["blockers"])


def test_bundle_hashes_detect_corruption_and_escape(tmp_path):
    model = tmp_path / "classifier.joblib"
    model.write_bytes(b"research model")
    digest = hashlib.sha256(model.read_bytes()).hexdigest()
    (tmp_path / "checksums.sha256").write_text(f"{digest}  classifier.joblib\n")
    assert readiness.verify_bundle(tmp_path)["valid"]
    model.write_bytes(b"tampered")
    assert readiness.verify_bundle(tmp_path)["errors"] == ["checksum mismatch: classifier.joblib", "no verified artifacts"]
    (tmp_path / "checksums.sha256").write_text(f"{digest}  ../outside.joblib\n")
    assert "checksum path escapes bundle" in readiness.verify_bundle(tmp_path)["errors"]


def test_operational_policy_requires_real_decisions_not_boolean_or_default_numbers():
    assert readiness.policy_errors({})
    policy = {"status": "approved", "approved_by": "operator", "approved_at_utc": "2026-10-15T00:00:00Z",
              "maximum_false_positives_per_10000_benign": 10, "minimum_recall": .9,
              "maximum_p95_latency_ms": 500, "intended_population": "fixture",
              "failure_behavior": "unavailable"}
    assert not readiness.policy_errors(policy)
    policy["minimum_recall"] = float("nan")
    assert any("minimum_recall" in error for error in readiness.policy_errors(policy))
    policy["minimum_recall"] = True
    assert any("minimum_recall" in error for error in readiness.policy_errors(policy))


def test_development_registry_is_never_reclassified_as_untouched(tmp_path):
    base = tmp_path / "lightgbm_dataset/fresh/external_holdouts"
    target = base / "fixture"
    target.mkdir(parents=True)
    registration = {"status": "development_benchmark", "operator_attested_model_metrics_uninspected": False,
                    "independent_evidence_coverage": 0, "existing_domain_overlap_count": 5}
    file = target / "registration.json"
    file.write_text(json.dumps(registration))
    (base / "registry.json").write_text(json.dumps({"runs": {"fixture": {
        "status": "development_benchmark", "registration_sha256": readiness.sha256(file)}}}))
    row = readiness.inspect_holdouts(tmp_path)[0]
    assert row["registration_hash_verified"]
    assert not row["qualified_untouched"]


def test_untouched_claim_needs_checksummed_independent_evidence(tmp_path):
    base = tmp_path / "lightgbm_dataset/fresh/external_holdouts"
    target = base / "fixture"
    target.mkdir(parents=True)
    registration = {"status": "untouched_external_holdout", "operator_attested_model_metrics_uninspected": True,
                    "independent_evidence_coverage": 1, "independent_evidence_label_matches": True,
                    "existing_domain_overlap_count": 0}
    file = target / "registration.json"
    file.write_text(json.dumps(registration))
    (base / "registry.json").write_text(json.dumps({"runs": {"fixture": {
        "status": "untouched_external_holdout", "registration_sha256": readiness.sha256(file)}}}))
    assert not readiness.inspect_holdouts(tmp_path)[0]["qualified_untouched"]


def test_release_bundle_needs_explicit_trust_anchor_and_complete_evaluation(tmp_path):
    (tmp_path / "classifier.txt").write_text("fake research model")
    (tmp_path / "checksums.sha256").write_text(f"{readiness.sha256(tmp_path / 'classifier.txt')}  classifier.txt\n")
    result = readiness.inspect_release_bundle(tmp_path)
    assert not result["verified"]
    assert any("trust anchor" in error for error in result["errors"])
    assert any("omits required files" in error for error in result["errors"])
    trusted = readiness.inspect_release_bundle(tmp_path, readiness.sha256(tmp_path / "checksums.sha256"))
    assert not trusted["verified"]
    assert any("did not pass" in error for error in trusted["errors"])
