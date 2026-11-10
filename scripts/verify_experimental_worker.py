"""Isolated deployment-image parity diagnostic; never loads a release verdict.

Uses only production inference dependencies and code, not research imports.
Inputs must be mounted read-only. This does not qualify or activate a model.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import sys
import time

STARTED = time.perf_counter()


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(root):
    root = Path(root).resolve()
    result = {}
    for line in (root / "checksums.sha256").read_text().splitlines():
        if not line.strip():
            continue
        expected, name = line.split("  ", 1)
        path = (root / name).resolve()
        if not re.fullmatch(r"[a-f0-9]{64}", expected) or name in result or not path.is_relative_to(root):
            raise ValueError("invalid_checksum_manifest")
        if not path.is_file() or sha(path) != expected:
            raise ValueError("artifact_checksum_mismatch")
        result[name] = expected
    if not result:
        raise ValueError("empty_checksum_manifest")
    return result


def bound(root, reference):
    root = Path(root).resolve()
    path = (root / reference["path"]).resolve()
    if not path.is_relative_to(root) or not path.is_file() or sha(path) != reference["sha256"]:
        raise ValueError("input_checksum_or_containment_failed")
    return path


def utc(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp_missing_timezone")
    return result


def limit(name):
    path = Path("/sys/fs/cgroup") / name
    return path.read_text().strip() if path.is_file() else None


def verify_reference_membership(rows, paths, frozen_expected):
    expected = {(path, row["capture_id"]) for row in rows for path in paths}
    if set(frozen_expected) != expected or len({row["capture_id"] for row in rows}) != len(rows):
        raise ValueError("host_reference_validation_membership_mismatch")


def independent_expected(row, raw_scan, component_results, contract, path):
    """Direct saved-evidence matrix interpretation, independent of runtime helpers."""
    quick = path == "quick_url"
    dom = raw_scan.get("browser_features", {}).get("dom", {})
    sandbox = raw_scan.get("sandbox_features", {})
    forms = sandbox.get("form_metrics", {}) if sandbox.get("sandbox_available", True) else {}
    consistency = raw_scan.get("consistency_report", {})
    raw_signals = {"browser_dom_form_count": dom.get("forms"), "browser_dom_script_count": dom.get("scripts"),
        "browser_dom_link_count": len(dom["links"]) if isinstance(dom.get("links"), list) else None,
        "sandbox_password_field_count": forms.get("password_field_count"),
        "sandbox_cross_domain_form_count": forms.get("cross_domain_form_count"),
        "consistency_score": consistency.get("consistency_score") if not consistency.get("reduced_confidence") else None,
        "consistency_cloaking_suspected": int(consistency["cloaking_suspected"])
            if type(consistency.get("cloaking_suspected")) is bool and not consistency.get("reduced_confidence") else None}
    values = []
    for feature in contract["features"]:
        namespace, name = feature["path"].split(".")
        indicator = name.endswith("_available")
        base = name.removesuffix("_available") if indicator else name
        if namespace == "components":
            if name == "url_probability":
                value = component_results["url"]["phishing_probability"]
            elif name == "visual_probability":
                value = None if quick else component_results["visual"]["phishing_probability"]
            else:
                value = 0 if quick else 1
        elif namespace == "scythe":
            observation = row["scythe"].get(base, {})
            available = not quick and observation.get("status") == "observed"
            observed = observation.get("value") if available else None
            if available and base == "ip_hosting_type":
                observed = contract["categorical_mapping"][base].get(observed)
                available = observed is not None
            value = int(available) if indicator else observed
        else:
            observed = None if quick else raw_signals[base]
            available = type(observed) in (int, float) and math.isfinite(observed) and observed >= 0
            if base.startswith("consistency_") and available:
                available = observed <= 1
            value = int(available) if indicator else (observed if available else None)
        values.append(float("nan") if value is None else float(value))
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--reference-sha256", required=True)
    parser.add_argument("--encoder-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, default=Path("/app"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--warm-scores-per-path", type=int, default=32)
    args = parser.parse_args()
    if args.output.exists() or args.warm_scores_per_path < 30:
        raise ValueError("output_exists_or_insufficient_warm_repeats")
    if sha(args.reference) != args.reference_sha256:
        raise ValueError("host_reference_checksum_mismatch")
    sys.path.insert(0, str(args.runtime_root))
    import numpy as np
    import lightgbm as lgb
    import torch
    from services import release_components as components
    from services import model_release as release
    from services.model_features import fusion_signals, scythe_observations
    imports_ms = (time.perf_counter() - STARTED) * 1000
    load_started = time.perf_counter()
    cohort, candidate = args.cohort.resolve(), args.candidate.resolve()
    cohort_files, hashes = verify(cohort), verify(candidate)
    reference = json.loads(args.reference.read_text())
    if (reference["candidate_checksums_sha256"] != sha(candidate / "checksums.sha256")
            or reference["cohort_checksums_sha256"] != sha(cohort / "checksums.sha256")):
        raise ValueError("host_reference_not_bound_to_frozen_inputs")
    contract = json.loads((candidate / "feature_contract.json").read_text())
    manifest = json.loads((candidate / "run_manifest.json").read_text())
    if contract.get("version") != "scythe_fusion_v2" or contract.get("positive_label") != 1 or manifest.get("release_approved") is not False or manifest.get("status") != "experimental_only":
        raise ValueError("not_expected_experimental_contract")
    expected_order = [feature["name"] for feature in contract["features"]]
    if len(expected_order) != 33:
        raise ValueError("wrong_fusion_dimensions")
    models = {}
    for path, descriptor in contract["fusion_by_path"].items():
        model = lgb.Booster(model_file=str(candidate / descriptor["artifact_file"]))
        if model.feature_name() != expected_order or model.num_model_per_iteration() != 1 or model.dump_model().get("objective", "").split()[0] != "binary":
            raise ValueError("native_feature_or_positive_class_orientation_mismatch")
        models[path] = model
    for requirements in contract["components_by_path"].values():
        for descriptor in requirements.values():
            components.verify_descriptor(candidate, hashes, descriptor)
            if descriptor["artifact_file"].endswith(".json"):
                head = json.loads((candidate / descriptor["artifact_file"]).read_text())
                if head.get("classes") != [0, 1]:
                    raise ValueError("component_positive_class_orientation_mismatch")
    model_load_ms = (time.perf_counter() - load_started) * 1000
    visual_descriptor = contract["components_by_path"]["deep_url"]["visual"]
    visual_contract = json.loads((candidate / visual_descriptor["contract_file"]).read_text())
    encoder_started = time.perf_counter()
    components._load_encoder(visual_contract, args.encoder_root)
    encoder_load_ms = (time.perf_counter() - encoder_started) * 1000
    all_rows = [json.loads(line) for line in (cohort / "manifest_paired.jsonl").read_text().splitlines()]
    rows = [row for row in all_rows if row["split"] == "validation"]
    if not rows or {row["label"] for row in rows} != {0, 1} or any(type(row["label"]) is not int for row in rows):
        raise ValueError("unexpected_validation_membership_or_label_orientation")
    frozen_expected = {}
    for record in reference["records"]:
        key = (record["path"], record["capture_id"])
        if record["status"] != "available":
            raise ValueError("host_reference_contains_unavailable_scores")
        if key in frozen_expected and abs(frozen_expected[key] - record["probability"]) > 1e-12:
            raise ValueError("inconsistent_host_reference_scores")
        frozen_expected[key] = record["probability"]
    verify_reference_membership(rows, models, frozen_expected)
    observations, raw_scans = {}, {}
    for row in rows:
        raw = json.loads(bound(cohort / "evidence", row["scan_evidence"]).read_text())
        if raw.get("capture_id") != row["capture_id"] or raw.get("url") != row["url"] or raw.get("captured_at") != row["captured_at"] or raw.get("decision_at") != row["decision_at"]:
            raise ValueError("saved_scan_identity_timestamp_mismatch")
        observed = {}
        for name, item in row["scythe"].items():
            if item.get("status") != "observed":
                observed[name] = item
                continue
            evidence = json.loads(bound(cohort / "evidence", item).read_text())
            if (evidence.get("capture_id") != row["capture_id"] or evidence.get("url") != row["url"]
                    or evidence.get("value") != item.get("value") or evidence.get("label_derived") is not False
                    or not 0 <= (utc(row["decision_at"]) - utc(item["observed_at"])).total_seconds() <= 3600):
                raise ValueError("saved_observation_identity_or_freshness_mismatch")
            observed[name] = {**item, "provider": evidence["provider"], "algorithm": evidence["algorithm_version"], "unit": evidence["unit"]}
        observations[row["capture_id"]] = observed
        raw_scans[row["capture_id"]] = raw

    def score(row, path, parity=False):
        raw = raw_scans[row["capture_id"]]
        image = bound(cohort / "evidence", row["screenshot"]) if path == "deep_url" else None
        results = components.score_components(candidate, hashes, contract["components_by_path"][path], row["url"], image, args.encoder_root)
        if any(result.get("status") != "observed" for result in results.values()):
            raise ValueError("component_unavailable_in_deployed_environment")
        values = {"component_results": results,
            "components": {"url_probability": results["url"]["phishing_probability"],
                "visual_probability": results.get("visual", {}).get("phishing_probability"),
                "visual_available": int(path == "deep_url")},
            "scythe": scythe_observations.extract_scythe_observations(observations[row["capture_id"]], contract, row["capture_id"], row["decision_at"]),
            "scan_signals": fusion_signals.extract_scan_signals(raw.get("browser_features"), raw.get("sandbox_features"), raw.get("consistency_report"))}
        if path == "quick_url":
            for namespace in ("scythe", "scan_signals"):
                values[namespace] = {key: 0 if key.endswith("_available") else None for key in values[namespace]}
        vector = release.build_vector(values, contract, path)
        if parity and not np.allclose(vector, independent_expected(row, raw, results, contract, path), equal_nan=True, atol=1e-12):
            raise ValueError("runtime_saved_evidence_feature_or_availability_parity_failed")
        probability = float(models[path].predict([vector], num_threads=1)[0])
        if not math.isfinite(probability) or not 0 <= probability <= 1:
            raise ValueError("invalid_native_probability")
        return probability

    parity_records = []
    for row in rows:
        cached = np.load(bound(cohort / "evidence", row["embedding"]), allow_pickle=False)
        encoded = components.encode_image(bound(cohort / "evidence", row["screenshot"]), visual_contract, args.encoder_root)
        if cached.shape != (512,) or cached.dtype != np.float32 or not np.allclose(cached, encoded, atol=1e-6):
            raise ValueError("linux_encoder_embedding_parity_failed")
        for path in ("quick_url", "deep_url"):
            probability = score(row, path, parity=True)
            delta = abs(probability - frozen_expected[(path, row["capture_id"])])
            if delta > 1e-10:
                raise ValueError("cross_version_native_prediction_parity_failed")
            parity_records.append({"capture_id": row["capture_id"], "label": row["label"], "path": path,
                "probability": probability, "host_probability_absolute_difference": delta,
                "max_embedding_absolute_difference": float(np.max(np.abs(cached - encoded)))})
    print(json.dumps({"parity": "passed", "records": len(parity_records)}), flush=True)
    summaries, timings = {}, []
    for path in ("quick_url", "deep_url"):
        durations = []
        for index in range(args.warm_scores_per_path):
            row = rows[index % len(rows)]
            started = time.perf_counter()
            probability = score(row, path)
            elapsed_ms = (time.perf_counter() - started) * 1000
            durations.append(elapsed_ms)
            timings.append({"path": path, "capture_id": row["capture_id"], "elapsed_ms": elapsed_ms, "probability": probability, "status": "available"})
        summaries[path] = {"scores": len(durations), "distinct_inputs": len(rows), "failures": 0,
            "p50_ms": float(np.percentile(durations, 50)), "p95_ms": float(np.percentile(durations, 95)),
            "maximum_ms": max(durations)}
        print(json.dumps({"completed": path, "summary": summaries[path]}), flush=True)
    from importlib.metadata import version
    dependencies = {name: version(name) for name in ("torch", "torchvision", "numpy", "scikit-learn", "lightgbm", "Pillow", "timm")}
    runtime_files = ["services/release_components.py", "services/model_release.py", "services/model_features/url_features.py",
                     "services/model_features/fusion_signals.py", "services/model_features/scythe_observations.py"]
    report = {"status": "passed_deployed_image_development_parity", "release_approved": False,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(), "image_id": args.image_id,
        "candidate_checksums_sha256": sha(candidate / "checksums.sha256"), "cohort_checksums_sha256": sha(cohort / "checksums.sha256"),
        "host_reference_sha256": args.reference_sha256, "verifier_sha256": sha(__file__),
        "verified_candidate_files": len(hashes), "verified_cohort_files": len(cohort_files),
        "runtime_source_sha256": {name: sha(args.runtime_root / name) for name in runtime_files},
        "dependencies": dependencies, "training_lightgbm_version": manifest["lightgbm_version"],
        "imports_ms": imports_ms, "cold_artifact_native_model_load_ms": model_load_ms, "cold_encoder_load_ms": encoder_load_ms,
        "warm": summaries, "parity": parity_records, "timings": timings,
        "resources": {"platform": platform.platform(), "machine": platform.machine(), "uid": os.getuid(),
            "cpu_max": limit("cpu.max"), "memory_max": limit("memory.max"), "pids_max": limit("pids.max"),
            "logical_cpu_count": os.cpu_count(), "torch_threads": torch.get_num_threads(), "lightgbm_predict_threads": 1},
        "limitations": ["Already inspected development validation only; not an untouched holdout or production quality qualification",
            "One-shot isolated container; Celery queue/task dispatch, capture, providers and complete scan latency are excluded",
            "Concurrent host workloads and filesystem caching were uncontrolled; cold stages are single observations",
            "Warm measurements include component/input validation, preprocessing, inference and saved observation/signal extraction",
            "No release artifact was activated and no independent reviewer attestations were created"]}
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    checksum = args.output.with_suffix(".sha256")
    checksum.write_text(f"{sha(args.output)}  {args.output.name}\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "output": str(args.output)}), flush=True)


if __name__ == "__main__":
    main()
