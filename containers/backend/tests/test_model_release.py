"""Release contracts cannot turn an experimental artifact into a live verdict."""
import hashlib
import json
from unittest.mock import Mock, patch

import pytest

from services.model_release import ReleaseUnavailable, build_vector, score_release, verify_release
from tasks.model_inference import infer


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
        evaluation["registration_sha256"] = sha256(reg_file)
        evaluation["holdout_sha256"] = sha256(holdout_file)
        evaluation["independent_evidence_sha256"] = sha256(indep_file)
        evaluation["predictions_sha256"] = sha256(preds_file)
        evaluation["exclusions_sha256"] = sha256(excl_file)
        evaluation["source_code_sha256"] = sha256(src_file)
        evaluation["protocol_sha256"] = sha256(proto_file)
    else:
        for key in ("registration_sha256", "holdout_sha256", "independent_evidence_sha256", "predictions_sha256", "exclusions_sha256", "source_code_sha256", "protocol_sha256"):
            evaluation[key] = hashlib.sha256(f"fixture_{key}".encode()).hexdigest()

    for metrics in evaluation["quality_by_path"].values():
        metrics["counts"] = {"tp": 1800, "fn": 200, "fp": 0, "tn": 5000, "unavailable": 0}
        metrics["latency_sample_count"] = 7000
        for success, total, key in ((1800, 2000, "recall_wilson95"), (0, 5000, "false_positive_rate_wilson95")):
            z = NormalDist().inv_cdf(.975); p = success / total; d = 1 + z * z / total
            c = (p + z * z / (2 * total)) / d; h = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / d
            metrics[key] = [max(0, c - h), min(1, c + h)]


def bundle(root):
    (root / "url.txt").write_text("fixture component bytes")
    (root / "url_contract.json").write_text(json.dumps({"version": "url_fixture_v1", "positive_label": 1}))
    descriptor = {"model_version": "url_fixture_v1", "artifact_file": "url.txt",
                  "artifact_sha256": hashlib.sha256((root / "url.txt").read_bytes()).hexdigest(),
                  "contract_file": "url_contract.json",
                  "contract_sha256": hashlib.sha256((root / "url_contract.json").read_bytes()).hexdigest()}
    contract = {"version": "fixture_v1", "positive_label": 1,
                "scoring_backend": "lightgbm_native_booster",
                "components_by_path": {"quick_url": {"url": descriptor}},
                "features": [{"name": "url_probability", "path": "components.url_probability",
                              "type": "number", "nullable": False, "minimum": 0, "maximum": 1}]}
    release = {"schema_version": 1, "status": "validated", "model_version": "fixture_v1",
               "feature_contract_version": "fixture_v1", "supported_paths": ["quick_url"]}
    policy = {"status": "approved", "minimum_recall": .8,
              "minimum_phishing_records": 2000, "minimum_benign_records": 5000, "minimum_coverage": 1, "require_wilson95_bounds": True,
              "maximum_false_positives_per_10000_benign": 100,
              "latency_limits_ms": {"quick_url": 2000}}
    thresholds = {"safe": .2, "low": .4, "medium": .7, "high": .85}
    files = {"release.json": release, "feature_contract.json": contract,
             "approved_policy.json": policy, "thresholds.json": thresholds}
    for name, value in files.items():
        (root / name).write_text(json.dumps(value))
    (root / "classifier.txt").write_text("fixture bytes; never load as a real model")
    evaluation = {**release, "status": "passed", "verified": True, "passed": True, "blockers": [],
                  "quality_by_path": {"quick_url": {"passed": True, "coverage": 1,
                    "recall_wilson95": [.81, .9], "false_positive_rate_wilson95": [0, .009],
                    "latency_p95_ms": 10}}}
    for key, name in {"model_sha256": "classifier.txt", "feature_contract_sha256": "feature_contract.json",
                      "policy_sha256": "approved_policy.json", "thresholds_sha256": "thresholds.json"}.items():
        evaluation[key] = hashlib.sha256((root / name).read_bytes()).hexdigest()
    complete_synthetic_evidence(evaluation, root)
    (root / "release_evaluation.json").write_text(json.dumps(evaluation))
    return rehash(root)


def rehash(root):
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}" for p in sorted(root.rglob("*"))
             if p.is_file() and p.name != "checksums.sha256"]
    manifest = root / "checksums.sha256"
    manifest.write_text("\n".join(lines) + "\n")
    return hashlib.sha256(manifest.read_bytes()).hexdigest()


def evidence(root=None):
    descriptor = (json.loads((root / "feature_contract.json").read_text())["components_by_path"]["quick_url"]["url"]
                  if root else {})
    return {"components": {"url_probability": .9}, "component_results": {
        "url": {"status": "observed", "artifact_hashes": descriptor}}}


def fusion_v2_contract(root, classifier_names):
    scythe = ("brand_homoglyph_detected", "domain_expiration_duration_days",
              "corporate_lookalike_distance", "hosting_provider_abuse_history",
              "open_threat_exchange_pulse_count", "url_shortener_used",
              "certificate_transparency_velocity", "ip_hosting_type")
    signals = ("browser_dom_form_count", "browser_dom_script_count", "browser_dom_link_count",
               "sandbox_password_field_count", "sandbox_cross_domain_form_count",
               "consistency_score", "consistency_cloaking_suspected")
    fields = [
        {"name": "url_probability", "path": "components.url_probability", "type": "number", "nullable": False, "minimum": 0, "maximum": 1},
        {"name": "visual_probability", "path": "components.visual_probability", "type": "number", "nullable": True, "minimum": 0, "maximum": 1},
        {"name": "visual_available", "path": "components.visual_available", "type": "number", "nullable": False, "minimum": 0, "maximum": 1},
    ]
    for name in scythe + signals:
        namespace = "scythe" if name in scythe else "scan_signals"
        fields.extend([
            {"name": name, "path": f"{namespace}.{name}", "type": "number", "nullable": True},
            {"name": name + "_available", "path": f"{namespace}.{name}_available", "type": "number", "nullable": False, "minimum": 0, "maximum": 1},
        ])
    component_descriptors = {}
    for kind in ("url", "visual"):
        artifact_name = f"{kind}.json"
        contract_name = f"{kind}_contract.json"
        (root / artifact_name).write_text("component fixture")
        (root / contract_name).write_text(json.dumps({"version": f"paired_{kind}_head_v2", "positive_label": 1}))
        component_descriptors[kind] = {"model_version": f"paired_{kind}_head_v2", "artifact_file": artifact_name,
            "artifact_sha256": hashlib.sha256((root / artifact_name).read_bytes()).hexdigest(),
            "contract_file": contract_name,
            "contract_sha256": hashlib.sha256((root / contract_name).read_bytes()).hexdigest()}
    names = [field["name"] for field in fields]
    fusion_by_path = {}
    components_by_path = {}
    for path, requirements in (("quick_url", {"url": component_descriptors["url"]}),
                               ("deep_url", component_descriptors)):
        model_name = classifier_names[path]
        fusion_by_path[path] = {"model_version": "scythe_fusion_v2",
            "feature_contract_version": "scythe_fusion_v2", "artifact_file": model_name,
            "artifact_sha256": hashlib.sha256((root / model_name).read_bytes()).hexdigest(),
            "feature_order": names, "threshold": .6}
        components_by_path[path] = requirements
    return {"version": "scythe_fusion_v2", "positive_label": 1,
        "scoring_backend": "lightgbm_native_booster", "features": fields,
        "components_by_path": components_by_path, "fusion_by_path": fusion_by_path,
        "observation_specs": {}, "categorical_mapping": {"ip_hosting_type": {"cloud": 2}}}


def v2_bundle(root):
    import lightgbm
    import numpy as np
    classifiers = {"quick_url": "quick_classifier.txt", "deep_url": "deep_classifier.txt"}
    scythe = ("brand_homoglyph_detected", "domain_expiration_duration_days",
              "corporate_lookalike_distance", "hosting_provider_abuse_history",
              "open_threat_exchange_pulse_count", "url_shortener_used",
              "certificate_transparency_velocity", "ip_hosting_type")
    signals = ("browser_dom_form_count", "browser_dom_script_count", "browser_dom_link_count",
               "sandbox_password_field_count", "sandbox_cross_domain_form_count",
               "consistency_score", "consistency_cloaking_suspected")
    feature_names = ["url_probability", "visual_probability", "visual_available"]
    feature_names += [item for name in scythe + signals for item in (name, name + "_available")]
    x = np.random.default_rng(42).normal(size=(40, 33))
    y = np.arange(40) % 2
    for path, filename in classifiers.items():
        fitted = lightgbm.LGBMClassifier(n_estimators=3, min_child_samples=2, verbosity=-1).fit(
            x, y if path == "quick_url" else 1 - y, feature_name=feature_names)
        fitted.booster_.save_model(str(root / filename))
    contract = fusion_v2_contract(root, classifiers)
    contract_path = root / "feature_contract.json"
    contract_path.write_text(json.dumps(contract))
    policy = {"status": "approved", "minimum_recall": .8,
        "minimum_phishing_records": 2000, "minimum_benign_records": 5000, "minimum_coverage": 1, "require_wilson95_bounds": True,
              "maximum_false_positives_per_10000_benign": 100,
        "latency_limits_ms": {"quick_url": 2000, "deep_url": 15000}}
    thresholds = {"deployment_threshold": True,
        "decision_thresholds": {"quick_url": .6, "deep_url": .6}}
    (root / "approved_policy.json").write_text(json.dumps(policy))
    (root / "thresholds.json").write_text(json.dumps(thresholds))
    for name, value in (("release.json", {"schema_version": 2, "status": "validated",
            "model_version": "fusion_fixture_v2", "feature_contract_version": "scythe_fusion_v2",
            "supported_paths": ["quick_url", "deep_url"], "classifiers_by_path": classifiers}),):
        (root / name).write_text(json.dumps(value))
    evaluation = {"schema_version": 1, "model_version": "fusion_fixture_v2",
        "feature_contract_version": "scythe_fusion_v2", "supported_paths": ["quick_url", "deep_url"],
        "verified": True, "passed": True, "blockers": [],
        "model_sha256_by_path": {path: contract["fusion_by_path"][path]["artifact_sha256"]
                                  for path in classifiers},
        "feature_contract_sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        "policy_sha256": hashlib.sha256((root / "approved_policy.json").read_bytes()).hexdigest(),
        "thresholds_sha256": hashlib.sha256((root / "thresholds.json").read_bytes()).hexdigest(),
        "quality_by_path": {path: {"passed": True, "coverage": 1,
            "recall_wilson95": [.81, .9], "false_positive_rate_wilson95": [0, .009],
            "latency_p95_ms": 100} for path in classifiers}}
    complete_synthetic_evidence(evaluation, root)
    (root / "release_evaluation.json").write_text(json.dumps(evaluation))
    return rehash(root), contract


def test_release_rejects_missing_or_changed_trust(tmp_path):
    digest = bundle(tmp_path)
    verify_release(str(tmp_path), digest)
    (tmp_path / "classifier.txt").write_text("corrupt")
    with pytest.raises(ReleaseUnavailable, match="checksum_mismatch"):
        verify_release(str(tmp_path), digest)


@pytest.mark.parametrize("change", ["passed", "verified", "binding", "quality", "coverage"])
def test_release_refuses_failed_or_mismatched_evidence(tmp_path, change):
    bundle(tmp_path)
    path = tmp_path / "release_evaluation.json"
    report = json.loads(path.read_text())
    if change in {"passed", "verified"}:
        report[change] = False
    elif change == "binding":
        report["model_sha256"] = "0" * 64
    elif change == "coverage":
        report["quality_by_path"]["quick_url"]["coverage"] = .9
    else:
        report["quality_by_path"]["quick_url"]["false_positive_rate_wilson95"][1] = .02
    path.write_text(json.dumps(report))
    with pytest.raises(ReleaseUnavailable):
        verify_release(str(tmp_path), rehash(tmp_path))


def test_exact_threshold_and_native_prediction_metadata(tmp_path):
    digest = bundle(tmp_path)
    with patch("services.model_release._load_native") as loader:
        loader.return_value.predict.return_value = [.7]
        report = score_release(str(tmp_path), digest, evidence(tmp_path), "quick_url")
    assert report["risk_level"] == "HIGH"
    assert report["is_placeholder"] is False and report["risk_score"] == 70
    assert report["release_manifest_sha256"] == digest


def test_component_hash_mismatch_and_unsupported_path_prevent_inference(tmp_path):
    digest = bundle(tmp_path)
    row = evidence(tmp_path)
    row["component_results"]["url"]["artifact_hashes"] = {}
    with patch("services.model_release._load_native") as load:
        with pytest.raises(ReleaseUnavailable, match="component_contract_mismatch"):
            score_release(str(tmp_path), digest, row, "quick_url")
        with pytest.raises(ReleaseUnavailable, match="unsupported_input_path"):
            score_release(str(tmp_path), digest, evidence(tmp_path), "deep_url")
        load.assert_not_called()


def test_feature_order_range_missingness_and_metadata_rejection():
    contract = {"features": [{"name": "x", "path": "components.url_probability", "type": "number", "minimum": 0, "maximum": 1}]}
    assert build_vector(evidence(), contract) == [.9]
    for value in [None, True, float("nan"), -1, 1.1]:
        with pytest.raises(ReleaseUnavailable):
            build_vector({"components": {"url_probability": value}}, contract)
    contract["features"][0]["path"] = "source.label"
    with pytest.raises(ReleaseUnavailable, match="invalid_contract"):
        build_vector({}, contract)


def test_disabled_or_missing_release_stays_unknown_without_component_inference():
    with patch("tasks.model_inference.settings.MODEL_RELEASE_ENABLED", False):
        assert infer({"url": "https://example.org"})["error_reason"] == "disabled"
    with patch("tasks.model_inference.settings.MODEL_RELEASE_ENABLED", True), \
            patch("tasks.model_inference.verify_release",
                  side_effect=ReleaseUnavailable("bundle_unavailable")) as verify:
        result = infer({"url": "https://example.org"})
    assert result["risk_score"] is None and result["is_placeholder"]
    assert result["error_reason"] == "bundle_unavailable"
    verify.assert_called_once()


def test_quick_api_delegates_and_worker_failure_is_unknown():
    from risk_fusion import run_risk_fusion
    job = Mock()
    job.get.side_effect = TimeoutError
    with patch("config.settings.MODEL_RELEASE_ENABLED", True), \
            patch("tasks.model_inference.model_inference_task.apply_async", return_value=job) as dispatch:
        result = run_risk_fusion({"url": "https://example.org/"})
    assert result["risk_level"] == "UNKNOWN" and result["probability"] is None
    assert dispatch.call_args.kwargs["queue"] == "models"


def test_quick_api_validates_path_specific_classification_threshold():
    from risk_fusion import run_risk_fusion
    result = {"risk_score": 65.0, "risk_level": "HIGH", "probability": .65,
        "is_placeholder": False, "availability": "observed", "model_version": "fixture_v2",
        "contract_version": "scythe_fusion_v2", "release_manifest_sha256": "a" * 64,
        "model_sha256": "b" * 64, "classification_threshold": .6}
    job = Mock()
    job.get.return_value = result
    with patch("config.settings.MODEL_RELEASE_ENABLED", True), \
            patch("tasks.model_inference.model_inference_task.apply_async", return_value=job):
        assert run_risk_fusion({"url": "https://example.org"})["risk_level"] == "HIGH"
        result["classification_threshold"] = .8
        rejected = run_risk_fusion({"url": "https://example.org"})
    assert rejected["risk_level"] == "UNKNOWN" and rejected["is_placeholder"]


def test_quick_cache_preserves_paths_and_includes_release_identity():
    from services.quickscan import _cache_key
    assert _cache_key("https://example.org/a/") != _cache_key("https://example.org/a")
    before = _cache_key("https://example.org/a")
    with patch("config.settings.MODEL_RELEASE_ENABLED", True), \
            patch("config.settings.MODEL_RELEASE_CHECKSUMS_SHA256", "a" * 64):
        assert _cache_key("https://example.org/a") != before


def test_native_release_prediction_matches_original_booster(tmp_path):
    import lightgbm
    import numpy as np
    bundle(tmp_path)
    x = np.linspace(0, 1, 80).reshape(-1, 1)
    fitted = lightgbm.LGBMClassifier(n_estimators=3, min_child_samples=2, verbosity=-1).fit(
        x, (x[:, 0] > .5).astype(int), feature_name=["url_probability"])
    fitted.booster_.save_model(str(tmp_path / "classifier.txt"))
    path = tmp_path / "release_evaluation.json"
    report = json.loads(path.read_text())
    report["model_sha256"] = hashlib.sha256((tmp_path / "classifier.txt").read_bytes()).hexdigest()
    path.write_text(json.dumps(report))
    result = score_release(str(tmp_path), rehash(tmp_path), evidence(tmp_path), "quick_url")
    assert result["probability"] == pytest.approx(fitted.predict_proba([[.9]])[0, 1], abs=1e-12)


def test_v2_release_uses_path_model_contract_and_binary_threshold(tmp_path):
    digest, contract = v2_bundle(tmp_path)
    descriptor = contract["components_by_path"]["quick_url"]["url"]
    values = {"components": {"url_probability": .9, "visual_probability": None, "visual_available": 0},
        "component_results": {"url": {"status": "observed", "artifact_hashes": descriptor}},
        "scythe": {}, "scan_signals": {}}
    for field in contract["features"][3:]:
        namespace, key = field["path"].split(".")
        values[namespace][key] = 0 if key.endswith("_available") else None
    result = score_release(str(tmp_path), digest, values, "quick_url")
    assert result["risk_level"] == ("HIGH" if result["probability"] >= .6 else "SAFE")
    assert result["classification_threshold"] == .6
    assert result["model_sha256"] == contract["fusion_by_path"]["quick_url"]["artifact_sha256"]
    assert result["is_placeholder"] is False
    deep_requirements = contract["components_by_path"]["deep_url"]
    deep_evidence = {"components": {"url_probability": .9, "visual_probability": .8,
        "visual_available": 1},
        "component_results": {"url": {"status": "observed", "artifact_hashes": deep_requirements["url"]},
                              "visual": {"status": "observed", "artifact_hashes": deep_requirements["visual"]}},
        "scythe": {}, "scan_signals": {}}
    for field in contract["features"][3:]:
        namespace, key = field["path"].split(".")
        deep_evidence[namespace][key] = 0 if key.endswith("_available") else None
    deep = score_release(str(tmp_path), digest, deep_evidence, "deep_url")
    assert deep["model_sha256"] == contract["fusion_by_path"]["deep_url"]["artifact_sha256"]
    assert deep["model_sha256"] != result["model_sha256"]


def test_v2_quick_rejects_deep_only_features_and_mismatched_availability(tmp_path):
    (tmp_path / "quick_classifier.txt").write_text("fixture")
    (tmp_path / "deep_classifier.txt").write_text("fixture")
    contract = fusion_v2_contract(tmp_path, {"quick_url": "quick_classifier.txt", "deep_url": "deep_classifier.txt"})
    evidence_row = {"components": {"url_probability": .2, "visual_probability": None, "visual_available": 0},
        "component_results": {"url": {"status": "observed"}}, "scythe": {}, "scan_signals": {}}
    for field in contract["features"][3:]:
        namespace, key = field["path"].split(".")
        evidence_row[namespace][key] = 0 if key.endswith("_available") else None
    vector = build_vector(evidence_row, contract, "quick_url")
    assert len(vector) == 33
    evidence_row["scan_signals"]["browser_dom_form_count"] = 1
    evidence_row["scan_signals"]["browser_dom_form_count_available"] = 1
    with pytest.raises(ReleaseUnavailable, match="invalid_evidence"):
        build_vector(evidence_row, contract, "quick_url")
    evidence_row["components"]["visual_available"] = 1
    with pytest.raises(ReleaseUnavailable, match="invalid_evidence"):
        build_vector(evidence_row, contract, "quick_url")


def test_release_verifier_accepts_multiple_checksum_bound_component_support_files(tmp_path):
    bundle(tmp_path)
    contract_path = tmp_path / "feature_contract.json"
    contract = json.loads(contract_path.read_text())
    first, second = tmp_path / "url_vectorizer.json", tmp_path / "url_metadata.json"
    first.write_text('{"vocabulary":{}}')
    second.write_text('{"format":"fixture"}')
    descriptor = contract["components_by_path"]["quick_url"]["url"]
    descriptor["support_files"] = [
        {"role": "vectorizer", "file": first.name, "sha256": hashlib.sha256(first.read_bytes()).hexdigest()},
        {"role": "metadata", "file": second.name, "sha256": hashlib.sha256(second.read_bytes()).hexdigest()},
    ]
    contract_path.write_text(json.dumps(contract))
    evaluation_path = tmp_path / "release_evaluation.json"
    evaluation = json.loads(evaluation_path.read_text())
    evaluation["feature_contract_sha256"] = hashlib.sha256(contract_path.read_bytes()).hexdigest()
    reg_file = tmp_path / "evidence" / "registration.json"
    if reg_file.is_file():
        reg = json.loads(reg_file.read_text())
        reg["bindings"]["feature_contract"]["sha256"] = evaluation["feature_contract_sha256"]
        reg_file.write_text(json.dumps(reg))
        evaluation["registration_sha256"] = sha256(reg_file)
    evaluation_path.write_text(json.dumps(evaluation))
    anchor = rehash(tmp_path)
    assert verify_release(str(tmp_path), anchor)[2]["components_by_path"]["quick_url"]["url"]["support_files"] == descriptor["support_files"]

    descriptor["support_files"][1]["sha256"] = "0" * 64
    contract_path.write_text(json.dumps(contract))
    evaluation["feature_contract_sha256"] = hashlib.sha256(contract_path.read_bytes()).hexdigest()
    if reg_file.is_file():
        reg = json.loads(reg_file.read_text())
        reg["bindings"]["feature_contract"]["sha256"] = evaluation["feature_contract_sha256"]
        reg_file.write_text(json.dumps(reg))
        evaluation["registration_sha256"] = sha256(reg_file)
    evaluation_path.write_text(json.dumps(evaluation))
    with pytest.raises(ReleaseUnavailable, match="component_contract_mismatch"):
        verify_release(str(tmp_path), rehash(tmp_path))


def test_terminal_websocket_event_waits_for_persistence(tmp_path):
    import tasks.risk_fusion as task
    from celery.exceptions import Retry
    with patch.object(task, "_scan_dir", return_value=str(tmp_path)), \
            patch.object(task, "_claim_scan", return_value=True), \
            patch.object(task, "_load_json", return_value={}), \
            patch.object(task, "_get_cyberintel", return_value={}), \
            patch.object(task, "_mark_status", return_value=False), \
            patch.object(task, "_redis_client"), \
            patch.object(task, "_push_websocket_update") as push, \
            patch.object(task.risk_fusion_task, "retry", side_effect=Retry):
        with pytest.raises(Retry):
            task.risk_fusion_task("87654321-4321-4321-9210-210987654321")
    push.assert_not_called()


@pytest.mark.parametrize("status", ["cancelled", "expired", "failed_timeout", "risk_fusion_done", "alert_pipeline_done"])
def test_late_fusion_cannot_restart_terminal_scan(status):
    import tasks.risk_fusion as task
    row = Mock(status=status)
    with patch.object(task, "_redis_client") as cache, \
            patch.object(task, "get_db_session") as sessions, \
            patch.object(task, "RiskFusionEngine") as engine:
        cache.set.return_value = True
        db = sessions.return_value.__enter__.return_value
        db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = row
        result = task.risk_fusion_task("87654321-4321-4321-9210-210987654321")
    assert result["status"] == "already_terminal"
    assert row.status == status
    db.commit.assert_not_called()
    engine.assert_not_called()


def test_live_fusion_lease_retries_without_recomputing():
    import tasks.risk_fusion as task
    from celery.exceptions import Retry
    with patch.object(task, "_redis_client") as cache, \
            patch.object(task, "_claim_scan") as claim, \
            patch.object(task.risk_fusion_task, "retry", side_effect=Retry) as retry:
        cache.set.return_value = False
        with pytest.raises(Retry):
            task.risk_fusion_task("87654321-4321-4321-9210-210987654321")
    assert retry.call_args.kwargs["countdown"] == 45
    claim.assert_not_called()


def test_unavailable_final_verdict_clears_preliminary_database_probability():
    import tasks.risk_fusion as task
    row = Mock(status="risk_fusion_running", risk_score=90, severity="HIGH")
    with patch.object(task, "get_db_session") as sessions:
        db = sessions.return_value.__enter__.return_value
        db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = row
        assert task._mark_status("87654321-4321-4321-9210-210987654321", "risk_fusion_done", None, "UNKNOWN")
    assert row.risk_score is None and row.severity == "UNKNOWN"


@pytest.mark.parametrize("problem", ["missing_policy_minimum", "lowered_policy_minimum", "missing_evidence", "missing_counts", "small_holdout", "forged_interval", "unavailable", "missing_latency_samples"])
def test_aggregate_passed_cannot_bypass_qualification(tmp_path, problem):
    bundle(tmp_path)
    policy_path = tmp_path / "approved_policy.json"
    evaluation_path = tmp_path / "release_evaluation.json"
    policy = json.loads(policy_path.read_text())
    evaluation = json.loads(evaluation_path.read_text())
    metrics = evaluation["quality_by_path"]["quick_url"]
    if problem == "missing_policy_minimum":
        policy.pop("minimum_phishing_records")
    elif problem == "lowered_policy_minimum":
        policy["minimum_benign_records"] = 2000
    elif problem == "missing_evidence":
        evaluation.pop("independent_evidence_sha256")
    elif problem == "missing_counts":
        metrics.pop("counts")
    elif problem == "small_holdout":
        metrics["counts"]["tp"] = 1217
        metrics["counts"]["fn"] = 0
        metrics["counts"]["tn"] = 2120
    elif problem == "forged_interval":
        metrics["recall_wilson95"] = [.99, 1]
    elif problem == "unavailable":
        metrics["counts"]["unavailable"] = 1
    elif problem == "missing_latency_samples":
        metrics.pop("latency_sample_count")
    policy_path.write_text(json.dumps(policy))
    evaluation["policy_sha256"] = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    evaluation_path.write_text(json.dumps(evaluation))
    with pytest.raises(ReleaseUnavailable, match="qualification_"):
        verify_release(str(tmp_path), rehash(tmp_path))
