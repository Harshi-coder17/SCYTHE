"""Evaluate pre-registered local release evidence without fitting or tuning models.

Inputs are a frozen registration and scorer-produced predictions. Registration
validation completes BEFORE predictions are opened. Exit 2 means blocked/failed.
The new output directory is immutable: this tool never overwrites an evaluation.
Evidence provenance is operator-reviewed; hashes establish integrity, not truth.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
from statistics import NormalDist
import sys
from urllib.parse import urlsplit, urlunsplit


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def utc(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps require UTC offset")
    return parsed.astimezone(timezone.utc)


def finite(value, minimum=0, maximum=None):
    return (not isinstance(value, bool) and isinstance(value, (float, int))
            and math.isfinite(value) and value >= minimum
            and (maximum is None or value <= maximum))


def wilson(successes, total):
    if not total:
        return [None, None]
    z = NormalDist().inv_cdf(.975)
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [max(0, center - half), min(1, center + half)]


def bound_file(base, binding):
    if not isinstance(binding, dict) or not binding.get("path") or not binding.get("sha256"):
        raise ValueError("missing path/checksum binding")
    path = (base / binding["path"]).resolve()
    if not path.is_file() or sha256(path) != binding["sha256"]:
        raise ValueError("missing or changed bound file: " + str(binding["path"]))
    return path


@lru_cache(maxsize=1)
def domain_extractor():
    import tldextract
    return tldextract.TLDExtract(suffix_list_urls=())


def domain_from_canonical(url):
    """Offline PSL grouping, identical default private-suffix policy to runtime."""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
    if parsed.scheme not in {"http", "https"} or not host or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("invalid canonical URL")
    authority = f"[{host}]" if ":" in host else host
    port = parsed.port
    if port is not None and not ((parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)):
        authority += f":{port}"
    canonical = urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, ""))
    if canonical != url:
        raise ValueError("URL is not canonical")
    extracted = domain_extractor()(host)
    return (getattr(extracted, "top_domain_under_public_suffix", None)
            or getattr(extracted, "registered_domain", None) or host)


def validate_registration(path):
    """Strict preflight. Never load predictions here or infer independent labels."""
    path = Path(path).resolve()
    registration = read_json(path)
    errors = []
    if registration.get("schema_version") != "scythe_release_registration_v2":
        errors.append("unsupported registration schema")
    if registration.get("status") != "untouched_external_holdout":
        errors.append("holdout is not registered untouched")
    if registration.get("operator_attested_model_metrics_uninspected") is not True:
        errors.append("missing pre-scoring noninspection attestation")
    if not registration.get("operator") or not registration.get("independent_evidence_reviewed_by"):
        errors.append("operator and independent evidence reviewer are required")
    if registration.get("labels_independently_supported") is not True:
        errors.append("independent historical labels not attested")
    if registration.get("all_existing_and_examined_groups_in_exclusions") is not True:
        errors.append("exclusion scope not attested")
    try:
        frozen_at = utc(registration["registered_at_utc"])
    except (KeyError, TypeError, ValueError):
        errors.append("invalid registration timestamp")
        frozen_at = None
    files = {}
    is_v2 = registration.get("feature_contract_version") == "scythe_fusion_v2"
    required_bindings = ["feature_contract", "policy", "thresholds", "cohort", "independent_evidence",
                         "excluded_groups", "source_code", "protocol"]
    required_bindings.append("models_by_path" if is_v2 else "model")
    for name in required_bindings:
        try:
            files[name] = bound_file(path.parent, registration.get("bindings", {}).get(name))
        except (OSError, TypeError, ValueError) as exc:
            errors.append(f"{name}: {exc}")
    if errors:
        return {"verified": False, "blockers": errors}
    policy = read_json(files["policy"])
    if (policy.get("status") != "approved" or not policy.get("approved_by")
            or not policy.get("approval_evidence") or not policy.get("approved_at_utc")):
        errors.append("policy needs attributable owner acceptance")
    try:
        if utc(policy["approved_at_utc"]) > frozen_at:
            errors.append("policy approval is later than registration")
    except (KeyError, TypeError, ValueError):
        errors.append("invalid policy approval timestamp")
    if policy.get("minimum_recall") != .8 or policy.get("maximum_false_positives_per_10000_benign") != 100:
        errors.append("policy must retain accepted recall>=0.8 and FPR<=0.01")
    if policy.get("require_wilson95_bounds") is not True:
        errors.append("confidence-bound acceptance required")
    if policy.get("minimum_benign_records") != 5000 or policy.get("minimum_phishing_records") != 2000:
        errors.append("release cohort minimum is 5000 benign and 2000 phishing")
    if policy.get("minimum_coverage") != 1:
        errors.append("release must count every registered supported-path input")
    if policy.get("failure_behavior") != "UNKNOWN/unavailable; no model-triggered blocking or incident":
        errors.append("unavailable behavior must fail closed")
    thresholds = read_json(files["thresholds"])
    paths = registration.get("supported_paths", [])
    if not paths or len(set(paths)) != len(paths) or not set(paths) <= {"quick_url", "deep_url"}:
        errors.append("unsupported scoring paths")
    budgets = policy.get("latency_limits_ms", {})
    if not set(paths) <= set(budgets):
        errors.append("missing path latency limits")
    if policy.get("maximum_task_latency_ms") != 60000:
        errors.append("task limit must remain 60 seconds")
    for name in paths:
        expected_budget = 2000 if name == "quick_url" else 15000
        if budgets.get(name) != expected_budget:
            errors.append("invalid accepted latency budget: " + name)
    contract = read_json(files["feature_contract"])
    if not registration.get("model_version") or not registration.get("feature_contract_version"):
        errors.append("model and contract versions required")
    contract_version = contract.get("feature_contract_version", contract.get("version"))
    if contract_version != registration.get("feature_contract_version"):
        errors.append("contract version differs from registration")
    model_sha256_by_path = None
    if is_v2:
        paths = registration.get("supported_paths", [])
        threshold_values = thresholds.get("decision_thresholds")
        if (thresholds.get("deployment_threshold") is not True
                or set(paths) != {"quick_url", "deep_url"}
                or not isinstance(threshold_values, dict) or set(threshold_values) != set(paths)
                or any(not finite(threshold_values.get(path_name), maximum=1)
                       or not 0 < threshold_values[path_name] < 1 for path_name in paths)):
            errors.append("v2 release requires frozen deployment thresholds for both paths")
        fusion_by_path = contract.get("fusion_by_path", {})
        if set(fusion_by_path) != set(paths):
            errors.append("v2 fusion artifacts differ from supported paths")
        else:
            for path_name in paths:
                descriptor = fusion_by_path[path_name]
                if (descriptor.get("feature_contract_version") != contract_version
                        or descriptor.get("threshold") != threshold_values.get(path_name)):
                    errors.append("v2 threshold or contract binding mismatch: " + path_name)
            registered_models = read_json(files["models_by_path"])
            if set(registered_models) != set(paths):
                errors.append("registered model manifest differs from supported paths")
            else:
                model_sha256_by_path = {}
                for path_name in paths:
                    descriptor = fusion_by_path[path_name]
                    binding = registered_models[path_name]
                    if (binding.get("path") != descriptor.get("artifact_file")
                            or binding.get("sha256") != descriptor.get("artifact_sha256")
                            or not isinstance(binding.get("sha256"), str)
                            or not re.fullmatch(r"[0-9a-f]{64}", binding["sha256"])):
                        errors.append("registered v2 model binding mismatch: " + path_name)
                    model_sha256_by_path[path_name] = descriptor.get("artifact_sha256")
    else:
        if set(thresholds) != {"safe", "low", "medium", "high"} or not all(finite(thresholds.get(key), maximum=1) for key in ("safe", "low", "medium", "high")):
            errors.append("severity thresholds need four frozen finite fractions")
        elif not 0 < thresholds["safe"] < thresholds["low"] < thresholds["medium"] < thresholds["high"] < 1:
            errors.append("severity thresholds must be strictly ordered")
    cohort = read_jsonl(files["cohort"])
    evidence = read_jsonl(files["independent_evidence"])
    exclusions = read_json(files["excluded_groups"])
    forbidden_domains = set(exclusions.get("registrable_domains", []))
    forbidden_urls = set(exclusions.get("canonical_urls", []))
    forbidden_campaigns = set(exclusions.get("campaign_groups", []))
    forbidden_visuals = set(exclusions.get("visual_groups", []))
    if not forbidden_domains or not exclusions.get("source_manifests"):
        errors.append("exclusions need existing domains and checksummed source manifests")
    for reference in exclusions.get("source_manifests", []):
        try:
            bound_file(files["excluded_groups"].parent, reference)
        except (OSError, TypeError, ValueError) as exc:
            errors.append("exclusion source manifest: " + str(exc))
    evidence_by_id = {}
    for row in evidence:
        sample_id = row.get("sample_id")
        if not sample_id or sample_id in evidence_by_id:
            errors.append("missing/duplicate evidence identity")
        evidence_by_id[sample_id] = row
    ids, urls = set(), set()
    counts = {0: 0, 1: 0}
    for row in cohort:
        sample_id, label = row.get("sample_id"), row.get("label")
        if not sample_id or sample_id in ids or label not in (0, 1) or isinstance(label, bool):
            errors.append("invalid/duplicate cohort identity or label")
            continue
        ids.add(sample_id)
        counts[label] += 1
        url, domain = row.get("canonical_url"), row.get("registrable_domain")
        if not url or url in urls or not domain:
            errors.append("canonical URL duplicates or missing domain")
        urls.add(url)
        try:
            if domain_from_canonical(url) != domain:
                errors.append("incorrect registrable domain: " + str(sample_id))
        except (ImportError, ValueError, TypeError, UnicodeError) as exc:
            errors.append(f"domain verification {sample_id}: {type(exc).__name__}")
        if (domain in forbidden_domains or url in forbidden_urls
                or (row.get("campaign_group") and row["campaign_group"] in forbidden_campaigns)
                or (row.get("visual_group") and row["visual_group"] in forbidden_visuals)):
            errors.append("training/development exclusion overlap: " + str(sample_id))
        if "deep_url" in paths:
            try:
                bound_file(files["cohort"].parent, row.get("image"))
            except (OSError, TypeError, ValueError) as exc:
                errors.append(f"image {sample_id}: {exc}")
        proof = evidence_by_id.get(sample_id, {})
        if (proof.get("label") != label or proof.get("canonical_url") != url
                or proof.get("independent") is not True
                or proof.get("basis") not in {"historical_publisher_adjudication", "documented_site_owner_control", "independent_historical_analysis"}):
            errors.append("independent label evidence absent/mismatched: " + str(sample_id))
        try:
            capture = utc(row["captured_at_utc"])
            observed = utc(proof["observed_at_utc"])
            if capture > frozen_at or observed > frozen_at or proof.get("captured_at_utc") != row["captured_at_utc"]:
                errors.append("capture/evidence must predate registration and refer to same capture")
            bound_file(files["independent_evidence"].parent, proof.get("evidence"))
        except (KeyError, TypeError, OSError, ValueError) as exc:
            errors.append(f"historical evidence {sample_id}: {exc}")
    if set(evidence_by_id) != ids:
        errors.append("evidence and cohort membership differ")
    for label, minimum in ((0, 5000), (1, 2000)):
        if counts[label] < minimum:
            errors.append(f"insufficient label {label} records: {counts[label]} < {minimum}")
    return {"verified": not errors, "blockers": list(dict.fromkeys(errors)), "registration": registration,
            "files": files, "policy": policy, "thresholds": thresholds,
            "model_sha256_by_path": model_sha256_by_path, "cohort": cohort}


def path_metrics(rows, labels, threshold, budget, policy):
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "unavailable": 0}
    latencies = []
    for row in rows:
        label = labels[row["sample_id"]]
        available = row.get("status") == "available" and finite(row.get("probability"), maximum=1)
        if not available:
            counts["unavailable"] += 1
        positive = available and row["probability"] >= threshold
        counts[("tp" if positive else "fn") if label else ("fp" if positive else "tn")] += 1
        latency = row.get("elapsed_ms")
        if finite(latency):
            latencies.append(latency)
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    recall_bounds, fpr_bounds = wilson(tp, tp + fn), wilson(fp, fp + tn)
    p95 = sorted(latencies)[math.ceil(.95 * len(latencies)) - 1] if latencies else None
    coverage = 1 - counts["unavailable"] / len(rows) if rows else 0
    passed = (bool(rows) and recall_bounds[0] is not None and fpr_bounds[1] is not None
              and recall_bounds[0] >= policy["minimum_recall"]
              and fpr_bounds[1] <= policy["maximum_false_positives_per_10000_benign"] / 10000
              and coverage >= policy["minimum_coverage"]
              and len(latencies) == len(rows) and p95 <= budget
              and max(latencies) <= policy["maximum_task_latency_ms"])
    probabilities = [(row["probability"], labels[row["sample_id"]]) for row in rows
                     if row.get("status") == "available" and finite(row.get("probability"), maximum=1)]
    ranking = ranking_metrics(probabilities)
    return {"counts": counts, "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            "false_positives_per_10000_benign": 10000 * fp / (fp + tn) if fp + tn else None,
            "recall_wilson95": recall_bounds, "false_positive_rate_wilson95": fpr_bounds,
            "coverage": coverage, "latency_p95_ms": p95,
            "latency_max_ms": max(latencies) if latencies else None,
            "latency_sample_count": len(latencies), "passed": passed, **ranking}


def ranking_metrics(pairs):
    """Average precision and rank AUC with tied scores grouped together."""
    positives = sum(label for _, label in pairs)
    negatives = len(pairs) - positives
    groups = {}
    for probability, label in pairs:
        group = groups.setdefault(probability, [0, 0])
        group[label] += 1
    tp = fp = 0
    ap = auc = 0.0
    for probability in sorted(groups, reverse=True):
        negative, positive = groups[probability]
        new_tp, new_fp = tp + positive, fp + negative
        if positives:
            ap += positive / positives * new_tp / (new_tp + new_fp)
        if positives and negatives:
            auc += (new_fp - fp) / negatives * (new_tp + tp) / (2 * positives)
        tp, fp = new_tp, new_fp
    bins = []
    ece = 0.0
    for index in range(10):
        members = [(p, y) for p, y in pairs if min(9, int(p * 10)) == index]
        confidence = sum(p for p, _ in members) / len(members) if members else None
        rate = sum(y for _, y in members) / len(members) if members else None
        if members:
            ece += len(members) / len(pairs) * abs(confidence - rate)
        bins.append({"lower": index / 10, "upper": (index + 1) / 10, "count": len(members),
                     "mean_probability": confidence, "phishing_fraction": rate})
    return {"pr_auc_average_precision": ap if positives else None,
            "roc_auc": auc if positives and negatives else None,
            "brier_score": sum((p - y) ** 2 for p, y in pairs) / len(pairs) if pairs else None,
            "ece10": ece if pairs else None, "reliability_bins": bins}


def evaluate(registration_path, predictions_path=None):
    result = {"schema_version": 1, "status": "failed", "passed": False, "verified": False,
              "generated_at_utc": datetime.now(timezone.utc).isoformat(), "blockers": []}
    checked = validate_registration(registration_path)
    result["blockers"] = checked["blockers"]
    if not checked["verified"]:
        return result
    registration, files = checked["registration"], checked["files"]
    result.update({"model_version": registration["model_version"],
                   "feature_contract_version": registration["feature_contract_version"],
                   "supported_paths": registration["supported_paths"],
                   "registration_sha256": sha256(registration_path)})
    hash_names = {"feature_contract": "feature_contract_sha256",
                  "policy": "policy_sha256", "thresholds": "thresholds_sha256",
                  "cohort": "holdout_sha256", "independent_evidence": "independent_evidence_sha256",
                  "excluded_groups": "exclusions_sha256", "source_code": "source_code_sha256", "protocol": "protocol_sha256"}
    if registration.get("feature_contract_version") == "scythe_fusion_v2":
        result["model_sha256_by_path"] = checked["model_sha256_by_path"]
    else:
        hash_names["model"] = "model_sha256"
    result.update({key: sha256(files[name]) for name, key in hash_names.items()})
    if predictions_path is None:
        result["blockers"].append("preflight passed; frozen scorer predictions are required for release")
        return result
    predictions = read_json(predictions_path)
    metadata = predictions.get("metadata", {})
    metadata_keys = ["feature_contract_sha256", "thresholds_sha256", "holdout_sha256", "registration_sha256", "source_code_sha256"]
    if registration.get("feature_contract_version") == "scythe_fusion_v2":
        if metadata.get("model_sha256_by_path") != result.get("model_sha256_by_path"):
            result["blockers"].append("prediction binding mismatch: model_sha256_by_path")
    else:
        metadata_keys.append("model_sha256")
    for key in metadata_keys:
        if metadata.get(key) != result[key]:
            result["blockers"].append("prediction binding mismatch: " + key)
    if metadata.get("warm_latency_includes_preprocessing_validation_inference") is not True or not metadata.get("target_hardware"):
        result["blockers"].append("target-hardware warm request latency evidence missing")
    try:
        if utc(metadata["started_at_utc"]) < utc(registration["registered_at_utc"]):
            result["blockers"].append("predictions predate registration")
    except (KeyError, TypeError, ValueError):
        result["blockers"].append("invalid prediction timestamp")
    labels = {row["sample_id"]: row["label"] for row in checked["cohort"]}
    result["quality_by_path"] = {}
    rows = predictions.get("records", [])
    paths = registration["supported_paths"]
    if any(row.get("path") not in paths for row in rows):
        result["blockers"].append("predictions include unsupported paths")
    for path in paths:
        selected = [row for row in rows if row.get("path") == path]
        if {row.get("sample_id") for row in selected} != set(labels) or len(selected) != len(labels):
            result["blockers"].append("prediction membership differs from frozen cohort: " + path)
            continue
        if any(row.get("status") not in {"available", "unavailable"}
               or (row.get("status") == "available" and not finite(row.get("probability"), maximum=1))
               or (row.get("status") == "unavailable" and row.get("probability") is not None) for row in selected):
            result["blockers"].append("invalid availability/probability: " + path)
        decision_threshold = (checked["thresholds"]["decision_thresholds"][path]
                              if registration.get("feature_contract_version") == "scythe_fusion_v2"
                              else checked["thresholds"]["medium"])
        metrics = path_metrics(selected, labels, decision_threshold, checked["policy"]["latency_limits_ms"][path], checked["policy"])
        result["quality_by_path"][path] = metrics
        source_by_id = {row["sample_id"]: row.get("source", "unknown") for row in checked["cohort"]}
        metrics["by_source"] = {source: path_metrics([row for row in selected if source_by_id[row["sample_id"]] == source], labels, decision_threshold, checked["policy"]["latency_limits_ms"][path], checked["policy"])
                                for source in sorted(set(source_by_id.values()))}
        if not metrics["passed"]:
            result["blockers"].append("quality, coverage or latency gate failed: " + path)
    result["predictions_sha256"] = sha256(predictions_path)
    # Verified describes provenance/integrity; quality may fail independently.
    result["verified"] = not any(not item.startswith("quality, coverage or latency gate failed:") for item in result["blockers"])
    result["passed"] = result["verified"] and not result["blockers"]
    result["status"] = "passed" if result["passed"] else "failed"
    result["limitations"] = ["Wilson intervals assume independent observations; residual campaign/domain dependence may remain.",
                             "Evidence authenticity requires independent reviewer judgment; checksums cannot establish label truth.",
                             "This command neither trains models nor authorizes unsupported scoring paths."]
    return result


def export_evidence(registration_path, predictions_path, output_dir, report):
    """Copy exact verified inputs; never rewrite registered source bytes."""
    checked = validate_registration(registration_path)
    if not checked["verified"] or not report.get("verified"):
        raise ValueError("cannot export unverified evidence")
    files = checked["files"]
    bindings = {"registration": Path(registration_path), "holdout": files["cohort"],
                "independent_evidence": files["independent_evidence"],
                "predictions": Path(predictions_path), "exclusions": files["excluded_groups"],
                "source_code": files["source_code"], "protocol": files["protocol"]}
    extensions = {"holdout": ".jsonl", "independent_evidence": ".jsonl", "source_code": ".tar.gz"}
    root = Path(output_dir) / "evidence"
    root.mkdir(parents=True, exist_ok=False)
    evidence_map = {}
    for key, source in bindings.items():
        target = root / (key + extensions.get(key, ".json"))
        expected = report[key + "_sha256"]
        shutil.copyfile(source, target)
        if sha256(target) != expected:
            raise ValueError("evidence changed during export: " + key)
        evidence_map["evidence/" + target.name] = expected
    # Preserve referenced images, adjudication documents and exclusion manifests
    # by content hash, with an index to their original registered references.
    dependencies = []
    for source, rows, key in (
            (files["cohort"], checked["cohort"], "image"),
            (files["independent_evidence"], read_jsonl(files["independent_evidence"]), "evidence"),
            (files["excluded_groups"], read_json(files["excluded_groups"]).get("source_manifests", []), None)):
        for row in rows:
            binding = row if key is None else row.get(key)
            if binding is None and key == "image":
                continue
            original = bound_file(source.parent, binding)
            target = root / "blobs" / binding["sha256"]
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(original, target)
            if sha256(target) != binding["sha256"]:
                raise ValueError("evidence dependency changed during export")
            dependencies.append({"source_file": str(source), "reference": binding,
                                 "packaged_file": "evidence/blobs/" + target.name})
            if key == "evidence":
                try:
                    primary_data = json.loads(original.read_text(encoding="utf-8"))
                    corrob = primary_data.get("independent_corroboration")
                    if isinstance(corrob, dict) and corrob.get("sha256"):
                        c_sha = corrob["sha256"]
                        c_candidates = [
                            source.parent / "evidence_blobs" / c_sha,
                            source.parent / "evidence" / "blobs" / c_sha,
                        ]
                        for c_file in c_candidates:
                            if c_file.is_file() and sha256(c_file) == c_sha:
                                c_target = root / "blobs" / c_sha
                                shutil.copyfile(c_file, c_target)
                                dependencies.append({"source_file": str(source), "reference": {"path": f"evidence_blobs/{c_sha}", "sha256": c_sha},
                                                     "packaged_file": "evidence/blobs/" + c_sha})
                                break
                except Exception:
                    pass
    (root / "dependency_index.json").write_text(json.dumps(dependencies, indent=2), encoding="utf-8")
    report["evidence_files"] = evidence_map


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--predictions", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--dataset-deps", type=Path, help="Trusted local dependencies including tldextract; no downloads")
    args = parser.parse_args()
    if args.dataset_deps:
        sys.path.insert(0, str(args.dataset_deps.resolve()))
    # Refuse any existing directory, even an incomplete run. Use a new version.
    args.output_dir.mkdir(parents=True, exist_ok=False)
    try:
        report = evaluate(args.registration, args.predictions)
        if report.get("verified") and args.predictions:
            export_evidence(args.registration, args.predictions, args.output_dir, report)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        report = {"schema_version": 1, "verified": False, "passed": False, "status": "failed", "blockers": [f"invalid evaluation input: {type(exc).__name__}: {exc}"]}
    target = args.output_dir / "release_evaluation.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    (args.output_dir / "checksums.sha256").write_text("".join(
        f"{sha256(file)}  {file.relative_to(args.output_dir).as_posix()}\n"
        for file in sorted(args.output_dir.rglob("*")) if file.is_file()), encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "verified": report["verified"], "blockers": report["blockers"], "report": str(target.resolve())}))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
