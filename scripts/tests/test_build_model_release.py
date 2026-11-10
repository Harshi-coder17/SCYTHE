"""Packaging fixtures are synthetic and must never be used as release evidence."""
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("build_model_release", Path(__file__).resolve().parents[1] / "build_model_release.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def complete_synthetic_evidence(evaluation, candidate=None):
    # Synthetic acceptance fixture; never real release evidence.
    from statistics import NormalDist
    import hashlib
    import math
    if candidate is not None:
        ev_dir = candidate / "evidence"
        ev_dir.mkdir(parents=True, exist_ok=True)
        reg_file = ev_dir / "registration.json"
        reg_file.write_text(json.dumps({"fixture": "synthetic_registration"}), encoding="utf-8")
        holdout_file = ev_dir / "holdout.jsonl"
        lines = [json.dumps({"sample_id": f"p_{i}", "label": 1, "registrable_domain": f"p{i}.example"}) for i in range(2000)] + [json.dumps({"sample_id": f"b_{j}", "label": 0, "registrable_domain": f"b{j}.example"}) for j in range(5000)]
        holdout_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        indep_file = ev_dir / "independent_evidence.jsonl"
        indep_file.write_text(json.dumps({"fixture": "independent_evidence"}) + "\n", encoding="utf-8")
        preds_file = ev_dir / "predictions.json"
        pred_records = []
        paths = evaluation.get("supported_paths", ["quick_url"])
        for path in paths:
            for i in range(1800):
                pred_records.append({"sample_id": f"p_{i}", "path": path, "probability": 0.9, "status": "available", "elapsed_ms": evaluation["quality_by_path"][path]["latency_p95_ms"]})
            for i in range(1800, 2000):
                pred_records.append({"sample_id": f"p_{i}", "path": path, "probability": 0.1, "status": "available", "elapsed_ms": evaluation["quality_by_path"][path]["latency_p95_ms"]})
            for j in range(5000):
                pred_records.append({"sample_id": f"b_{j}", "path": path, "probability": 0.01, "status": "available", "elapsed_ms": evaluation["quality_by_path"][path]["latency_p95_ms"]})
        preds_file.write_text(json.dumps({"records": pred_records}), encoding="utf-8")
        excl_file = ev_dir / "exclusions.json"
        excl_file.write_text(json.dumps({"fixture": "exclusions"}), encoding="utf-8")
        src_file = ev_dir / "source_code.tar.gz"
        src_file.write_text("synthetic_source_fixture", encoding="utf-8")
        proto_file = ev_dir / "protocol.json"
        proto_file.write_text(json.dumps({"fixture": "protocol"}), encoding="utf-8")
        # Complete structural evidence for a synthetic release; no real labels.
        rows = [json.loads(line) for line in holdout_file.read_text().splitlines()]
        for row in rows:
            row.update(canonical_url="https://" + row["registrable_domain"] + "/", captured_at_utc="2026-10-01T00:00:00Z")
        holdout_file.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
        blob = json.dumps({"synthetic_fixture": True}).encode("utf-8")
        blob_hash = hashlib.sha256(blob).hexdigest()
        (ev_dir / "blobs").mkdir(exist_ok=True)
        (ev_dir / "blobs" / blob_hash).write_bytes(blob)
        proofs = [{**row, "independent": True, "basis": "independent_historical_analysis",
                   "observed_at_utc": "2026-10-01T01:00:00Z", "evidence": {"sha256": blob_hash}} for row in rows]
        indep_file.write_text("\n".join(json.dumps(row) for row in proofs), encoding="utf-8")
        registration = {"schema_version": "scythe_release_registration_v2", "status": "untouched_external_holdout",
                        "operator": "synthetic fixture", "independent_evidence_reviewed_by": "synthetic fixture",
                        "operator_attested_model_metrics_uninspected": True, "labels_independently_supported": True,
                        "all_existing_and_examined_groups_in_exclusions": True, "registered_at_utc": "2026-10-02T00:00:00Z",
                        **{key: evaluation.get(key) for key in ("model_version", "feature_contract_version", "supported_paths")}, "bindings": {}}
        for key, file in {"cohort": holdout_file, "independent_evidence": indep_file, "excluded_groups": excl_file,
                          "source_code": src_file, "protocol": proto_file}.items():
            registration["bindings"][key] = {"sha256": hashlib.sha256(file.read_bytes()).hexdigest()}
        for key in ("policy", "thresholds", "feature_contract"):
            registration["bindings"][key] = {"sha256": evaluation.get(key + "_sha256")}
        reg_file.write_text(json.dumps(registration), encoding="utf-8")
        evaluation["registration_sha256"] = builder.sha256(reg_file)
        evaluation["holdout_sha256"] = builder.sha256(holdout_file)
        evaluation["independent_evidence_sha256"] = builder.sha256(indep_file)
        evaluation["predictions_sha256"] = builder.sha256(preds_file)
        evaluation["exclusions_sha256"] = builder.sha256(excl_file)
        evaluation["source_code_sha256"] = builder.sha256(src_file)
        evaluation["protocol_sha256"] = builder.sha256(proto_file)
    else:
        for key in ("registration_sha256", "holdout_sha256", "independent_evidence_sha256", "predictions_sha256", "exclusions_sha256", "source_code_sha256", "protocol_sha256"):
            evaluation[key] = hashlib.sha256(f"fixture_{key}".encode()).hexdigest()

    for metrics in evaluation["quality_by_path"].values():
        metrics["counts"] = {"tp": 1800, "fn": 200, "fp": 0, "tn": 5000, "unavailable": 0}
        metrics["latency_sample_count"] = 7000
        for success, total, key in ((1800, 2000, "recall_wilson95"), (0, 5000, "false_positive_rate_wilson95")):
            z = NormalDist().inv_cdf(.975)
            p = success / total
            d = 1 + z * z / total
            c = (p + z * z / (2 * total)) / d
            h = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / d
            metrics[key] = [max(0, c - h), min(1, c + h)]


def write(path, data, candidate=None):
    if "quality_by_path" in data:
        complete_synthetic_evidence(data, candidate)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def package_inputs(tmp_path):
    candidate = tmp_path / "synthetic-candidate"
    candidate.mkdir()
    (candidate / "classifier.txt").write_text("synthetic fixture: not a trained model")
    components = candidate / "components"
    components.mkdir()
    (components / "url.txt").write_text("synthetic component: not a trained model")
    write(components / "url_contract.json", {"version": "url_fixture_v1", "positive_label": 1})
    descriptor = {"artifact_file": "components/url.txt", "artifact_sha256": builder.sha256(components / "url.txt"), "contract_file": "components/url_contract.json", "contract_sha256": builder.sha256(components / "url_contract.json"), "model_version": "url_fixture_v1"}
    write(candidate / "feature_contract.json", {"version": "fixture_v1", "positive_label": 1, "scoring_backend": "lightgbm_native_booster",
                                               "features": [{"name": "url_probability", "path": "components.url_probability", "type": "number", "nullable": False, "minimum": 0, "maximum": 1}],
                                               "components_by_path": {"quick_url": {"url": descriptor}}})
    policy = write(tmp_path / "policy.json", {"status": "approved", "minimum_recall": .8, "minimum_phishing_records": 2000, "minimum_benign_records": 5000, "minimum_coverage": 1, "require_wilson95_bounds": True, "maximum_false_positives_per_10000_benign": 100, "latency_limits_ms": {"quick_url": 2000}, "maximum_task_latency_ms": 60000, "allowed_actions": []})
    thresholds = write(tmp_path / "thresholds.json", {"safe": .1, "low": .3, "medium": .5, "high": .9})
    eval_data = {"schema_version": 1, "verified": True, "passed": True, "blockers": [], "model_version": "synthetic_fixture_never_deploy", "feature_contract_version": "fixture_v1", "supported_paths": ["quick_url"],
                 "model_sha256": builder.sha256(candidate / "classifier.txt"), "feature_contract_sha256": builder.sha256(candidate / "feature_contract.json"), "policy_sha256": builder.sha256(policy), "thresholds_sha256": builder.sha256(thresholds),
                 "quality_by_path": {"quick_url": {"passed": True, "coverage": 1, "recall_wilson95": [.99, 1], "false_positive_rate_wilson95": [0, .001], "latency_p95_ms": 100}}}
    complete_synthetic_evidence(eval_data, candidate)
    checksums = candidate / "checksums.sha256"
    checksums.write_text("".join(f"{builder.sha256(file)}  {file.relative_to(candidate).as_posix()}\n" for file in sorted(candidate.rglob('*')) if file.is_file() and file != checksums))
    evaluation = tmp_path / "evaluation.json"
    evaluation.write_text(json.dumps(eval_data), encoding="utf-8")
    return candidate, builder.sha256(checksums), evaluation, policy, thresholds, tmp_path / "release"


def test_build_finalizes_only_after_runtime_verification_and_does_not_activate(package_inputs):
    result = builder.build_release(*package_inputs)
    output = package_inputs[-1]
    assert result["status"] == "packaged_verified_not_activated"
    assert result["enabled"] is False
    assert output.is_dir() and not output.with_name("release.staging").exists()
    verified = builder.runtime_module().verify_release(str(output), result["checksums_sha256"])
    assert verified[1]["model_version"] == "synthetic_fixture_never_deploy"
    with pytest.raises(FileExistsError):
        builder.build_release(*package_inputs)


@pytest.mark.parametrize("problem", ["candidate_hash", "traversal", "policy_mismatch", "failed_evaluation", "missing_evaluation"])
def test_bad_inputs_never_create_final_release(package_inputs, problem):
    values = list(package_inputs)
    if problem == "candidate_hash":
        values[1] = "0" * 64
    elif problem == "traversal":
        manifest = values[0] / "checksums.sha256"
        manifest.write_text(f"{'0' * 64}  ../escape\n")
        values[1] = builder.sha256(manifest)
    elif problem == "policy_mismatch":
        values[3].write_text("{}")
    elif problem == "failed_evaluation":
        evaluation = builder.read_json(values[2])
        evaluation["passed"] = False
        write(values[2], evaluation)
    elif problem == "missing_evaluation":
        values[2].unlink()
    with pytest.raises((ValueError, OSError)):
        builder.build_release(*values)
    assert not values[-1].exists()


def test_failed_runtime_verification_preserves_staging_without_finalizing(package_inputs, monkeypatch):
    class InvalidRuntime:
        @staticmethod
        def verify_release(*_):
            raise ValueError("fixture verification failure")
    monkeypatch.setattr(builder, "runtime_module", lambda: InvalidRuntime)
    with pytest.raises(ValueError, match="verification failure"):
        builder.build_release(*package_inputs)
    output = package_inputs[-1]
    assert not output.exists()
    assert output.with_name("release.staging").exists()
    with pytest.raises(FileExistsError):
        builder.build_release(*package_inputs)


def test_v2_release_builder_requires_dual_path_artifacts_and_frozen_thresholds(tmp_path):
    candidate = tmp_path / "candidate-v2"
    candidate.mkdir()
    model_names = {"quick_url": "quick_classifier.txt", "deep_url": "deep_classifier.txt"}
    for name in model_names.values():
        (candidate / name).write_text(f"synthetic fixture {name}")
    expected_names = ["url_probability", "visual_probability", "visual_available"]
    scythe = ("brand_homoglyph_detected", "domain_expiration_duration_days",
              "corporate_lookalike_distance", "hosting_provider_abuse_history",
              "open_threat_exchange_pulse_count", "url_shortener_used",
              "certificate_transparency_velocity", "ip_hosting_type")
    signals = ("browser_dom_form_count", "browser_dom_script_count", "browser_dom_link_count",
               "sandbox_password_field_count", "sandbox_cross_domain_form_count",
               "consistency_score", "consistency_cloaking_suspected")
    expected_names += [item for name in scythe + signals for item in (name, name + "_available")]
    fusion_by_path = {path: {"model_version": "scythe_fusion_v2",
        "feature_contract_version": "scythe_fusion_v2", "artifact_file": filename,
        "artifact_sha256": builder.sha256(candidate / filename), "feature_order": expected_names,
        "threshold": .7, "threshold_policy": "frozen_validation_selection",
        "deployment_threshold": False} for path, filename in model_names.items()}
    feature_rows = [
        {"name": "url_probability", "path": "components.url_probability", "type": "number", "nullable": False, "minimum": 0, "maximum": 1},
        {"name": "visual_probability", "path": "components.visual_probability", "type": "number", "nullable": True, "minimum": 0, "maximum": 1},
        {"name": "visual_available", "path": "components.visual_available", "type": "number", "nullable": False, "minimum": 0, "maximum": 1},
    ]
    for name in scythe + signals:
        namespace = "scythe" if name in scythe else "scan_signals"
        feature_rows.extend([
            {"name": name, "path": f"{namespace}.{name}", "type": "number", "nullable": True},
            {"name": name + "_available", "path": f"{namespace}.{name}_available", "type": "number", "nullable": False, "minimum": 0, "maximum": 1},
        ])
    write(candidate / "feature_contract.json", {"version": "scythe_fusion_v2",
        "positive_label": 1, "scoring_backend": "lightgbm_native_booster", "features": feature_rows,
        "components_by_path": {"quick_url": {"url": {}}, "deep_url": {"url": {}, "visual": {}}},
        "fusion_by_path": fusion_by_path})
    components = candidate / "components"
    components.mkdir()
    for name, version in (("url", "url_char_tfidf_v1"), ("visual", "paired_visual_head_v2")):
        artifact = components / f"{name}.json"
        contract = components / f"{name}_contract.json"
        artifact.write_text(f"synthetic {name}")
        component_contract = {"version": version, "positive_label": 1}
        if name == "url":
            component_contract.update({"scoring_backend": "url_char_tfidf_linear_v1",
                "feature_contract": {"analyzer": "char", "ngram_range": [3, 5],
                    "max_features": 100000, "lowercase": True, "sublinear_tf": True}})
        write(contract, component_contract)
        descriptor = {"model_version": version, "artifact_file": artifact.relative_to(candidate).as_posix(),
            "artifact_sha256": builder.sha256(artifact), "contract_file": contract.relative_to(candidate).as_posix(),
            "contract_sha256": builder.sha256(contract)}
        if name == "url":
            support_files = []
            for role, filename in (("vectorizer", "url_vectorizer.json"), ("metadata", "url_metadata.json")):
                support = candidate / "components" / filename
                write(support, {"fixture": role})
                support_files.append({"role": role, "file": support.relative_to(candidate).as_posix(),
                    "sha256": builder.sha256(support)})
            descriptor["support_files"] = support_files
        for path in ("quick_url", "deep_url") if name == "url" else ("deep_url",):
            data = json.loads((candidate / "feature_contract.json").read_text())
            data["components_by_path"][path][name] = descriptor
            write(candidate / "feature_contract.json", data)
    contract_hash = builder.sha256(candidate / "feature_contract.json")
    policy = write(tmp_path / "policy-v2.json", {"status": "approved", "minimum_recall": .8,
        "minimum_phishing_records": 2000, "minimum_benign_records": 5000, "minimum_coverage": 1, "require_wilson95_bounds": True, "maximum_false_positives_per_10000_benign": 100,
        "latency_limits_ms": {"quick_url": 2000, "deep_url": 15000}, "allowed_actions": []})
    thresholds = write(tmp_path / "thresholds-v2.json", {"deployment_threshold": True,
        "decision_thresholds": {"quick_url": .7, "deep_url": .7}})
    eval_data = {"schema_version": 1,
        "verified": True, "passed": True, "blockers": [], "model_version": "fixture_v2",
        "feature_contract_version": "scythe_fusion_v2", "supported_paths": ["quick_url", "deep_url"],
        "model_sha256_by_path": {path: fusion_by_path[path]["artifact_sha256"] for path in model_names},
        "feature_contract_sha256": contract_hash, "policy_sha256": builder.sha256(policy),
        "thresholds_sha256": builder.sha256(thresholds), "quality_by_path": {
            path: {"passed": True, "coverage": 1, "recall_wilson95": [.81, .9],
                   "false_positive_rate_wilson95": [0, .009], "latency_p95_ms": 100}
            for path in model_names}}
    complete_synthetic_evidence(eval_data, candidate)
    candidate_manifest = candidate / "checksums.sha256"
    candidate_manifest.write_text("".join(f"{builder.sha256(file)}  {file.relative_to(candidate).as_posix()}\n"
        for file in sorted(candidate.rglob("*")) if file.is_file() and file != candidate_manifest))
    candidate_hash = builder.sha256(candidate_manifest)
    evaluation = tmp_path / "evaluation-v2.json"
    evaluation.write_text(json.dumps(eval_data), encoding="utf-8")
    output = tmp_path / "release-v2"
    result = builder.build_release(candidate, candidate_hash, evaluation, policy, thresholds, output)
    assert result["enabled"] is False
    assert result["status"] == "packaged_verified_not_activated"
    verified = builder.runtime_module().verify_release(str(output), result["checksums_sha256"])
    assert verified[1]["schema_version"] == 2
    assert (output / "components/url_vectorizer.json").is_file()
    assert (output / "components/url_metadata.json").is_file()


def test_v2_release_builder_rejects_experimental_thresholds(tmp_path):
    # A trainer-selected threshold cannot be mistaken for a release decision.
    candidate = tmp_path / "candidate-v2"
    candidate.mkdir()
    (candidate / "quick_classifier.txt").write_text("synthetic quick")
    (candidate / "deep_classifier.txt").write_text("synthetic deep")
    write(candidate / "feature_contract.json", {"version": "scythe_fusion_v2", "fusion_by_path": {}})
    manifest = candidate / "checksums.sha256"
    manifest.write_text("".join(f"{builder.sha256(file)}  {file.name}\n"
        for file in sorted(candidate.iterdir()) if file != manifest))
    policy = write(tmp_path / "policy.json", {"status": "approved"})
    thresholds = write(tmp_path / "thresholds.json", {"deployment_threshold": False,
        "decision_thresholds": {"quick_url": .5, "deep_url": .5}})
    evaluation = write(tmp_path / "evaluation.json", {"schema_version": 1, "passed": True,
        "verified": True, "blockers": []})
    with pytest.raises(ValueError, match="qualified path-specific deployment thresholds"):
        builder.build_release(candidate, builder.sha256(manifest), evaluation, policy,
                              thresholds, tmp_path / "release")


@pytest.mark.parametrize("problem", ["counts", "evidence", "minimum"])
def test_packaging_rejects_aggregate_only_qualification(package_inputs, problem):
    candidate, anchor, evaluation_path, policy_path, thresholds, output = package_inputs
    evaluation = builder.read_json(evaluation_path)
    if problem == "counts":
        evaluation["quality_by_path"]["quick_url"].pop("counts")
    elif problem == "evidence":
        evaluation.pop("holdout_sha256")
    else:
        policy = builder.read_json(policy_path)
        policy.pop("minimum_benign_records")
        policy_path.write_text(json.dumps(policy))
        evaluation["policy_sha256"] = builder.sha256(policy_path)
    evaluation_path.write_text(json.dumps(evaluation))
    with pytest.raises(ValueError, match="qualification_"):
        builder.build_release(candidate, anchor, evaluation_path, policy_path, thresholds, output)
    assert not output.exists()
