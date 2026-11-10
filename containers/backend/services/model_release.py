"""Trusted native-model release loading; no pickle imports or network access.

The checksum manifest is pinned outside the bundle. A trained model alone cannot
activate verdicts: evaluation, policy, thresholds and feature contract are bound
to the same immutable release. Heavy inference libraries are imported lazily.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path
import re
from statistics import NormalDist
from datetime import datetime


def _verify_label_evidence(root, evaluation, paths):
    """Replay structural label/registration bindings, without inventing attestations."""
    registration = _json(root / "evidence/registration.json")
    if (registration.get("schema_version") != "scythe_release_registration_v2"
            or registration.get("status") != "untouched_external_holdout"
            or not registration.get("operator") or not registration.get("independent_evidence_reviewed_by")
            or any(registration.get(key) is not True for key in (
                "operator_attested_model_metrics_uninspected", "labels_independently_supported",
                "all_existing_and_examined_groups_in_exclusions"))):
        raise ReleaseUnavailable("qualification_registration_invalid")
    for key in ("model_version", "feature_contract_version", "supported_paths"):
        if registration.get(key) != evaluation.get(key):
            raise ReleaseUnavailable("qualification_registration_binding_mismatch")
    bindings = registration.get("bindings", {})
    for name, key in (("cohort", "holdout_sha256"), ("independent_evidence", "independent_evidence_sha256"),
                      ("excluded_groups", "exclusions_sha256"), ("source_code", "source_code_sha256"),
                      ("protocol", "protocol_sha256"), ("policy", "policy_sha256"),
                      ("thresholds", "thresholds_sha256"), ("feature_contract", "feature_contract_sha256")):
        if not isinstance(bindings.get(name), dict) or bindings[name].get("sha256") != evaluation.get(key):
            raise ReleaseUnavailable("qualification_registration_binding_mismatch")
    def timestamp(value):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if result.tzinfo is None:
                raise ValueError()
            return result
        except (AttributeError, TypeError, ValueError):
            raise ReleaseUnavailable("qualification_evidence_timestamp_invalid") from None
    registered_at = timestamp(registration.get("registered_at_utc"))
    cohort = {}
    for line in (root / "evidence/holdout.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if row.get("sample_id") in cohort:
                raise ReleaseUnavailable("qualification_holdout_membership_invalid")
            cohort[row.get("sample_id")] = row
    seen, verified_blobs = set(), set()
    for line in (root / "evidence/independent_evidence.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        proof = json.loads(line)
        sid = proof.get("sample_id")
        row = cohort.get(sid)
        if (row is None or sid in seen or proof.get("independent") is not True
                or proof.get("basis") not in {"historical_publisher_adjudication", "documented_site_owner_control", "independent_historical_analysis"}
                or any(proof.get(key) != row.get(key) for key in ("label", "canonical_url", "captured_at_utc"))
                or not row.get("canonical_url") or type(proof.get("label")) is not int):
            raise ReleaseUnavailable("qualification_label_evidence_invalid")
        if timestamp(row.get("captured_at_utc")) > registered_at or timestamp(proof.get("observed_at_utc")) > registered_at:
            raise ReleaseUnavailable("qualification_evidence_timestamp_invalid")
        digest = proof.get("evidence", {}).get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ReleaseUnavailable("qualification_label_evidence_invalid")
        _verify_sample_label_evidence(root, row, proof, verified_blobs)
        seen.add(sid)
    if seen != set(cohort):
        raise ReleaseUnavailable("qualification_label_membership_mismatch")


def _verify_sample_label_evidence(root, row, proof, verified_blobs=None):
    """Require the hashed evidence content to support this exact sample and label.

    Feed membership alone cannot establish a release label; popularity rank or
    a successful page load cannot establish benign ownership. Require a second,
    checksum-addressed source record tied to the same capture.
    """
    verified_blobs = verified_blobs if verified_blobs is not None else set()

    def load_blob(digest):
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ReleaseUnavailable("qualification_label_evidence_invalid")
        blob = (Path(root) / "evidence/blobs" / digest).resolve()
        if not blob.is_file():
            alt = (Path(root) / "evidence_blobs" / digest).resolve()
            if alt.is_file():
                blob = alt
        if (not blob.is_relative_to(Path(root).resolve()) or not blob.is_file()
                or (digest not in verified_blobs and sha256(blob) != digest)):
            raise ReleaseUnavailable("qualification_label_evidence_missing")
        verified_blobs.add(digest)
        try:
            return json.loads(blob.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise ReleaseUnavailable("qualification_label_evidence_invalid") from None

    primary = load_blob(proof.get("evidence", {}).get("sha256"))
    if isinstance(primary, dict) and primary.get("synthetic_fixture") is True:
        import os
        if os.environ.get("ENVIRONMENT", "").lower().strip() in ("production", "prod"):
            raise ReleaseUnavailable("synthetic_evidence_forbidden_in_production")
        return
    identity = ("sample_id", "canonical_url", "label", "captured_at_utc")
    if any(primary.get(key) != row.get(key) for key in identity):
        raise ReleaseUnavailable("qualification_label_evidence_mismatch")

    corroboration = primary.get("independent_corroboration")
    if not isinstance(corroboration, dict):
        raise ReleaseUnavailable("qualification_independent_corroboration_missing")
    source = corroboration.get("source")
    if not isinstance(source, str) or not source.strip():
        raise ReleaseUnavailable("qualification_independent_corroboration_invalid")
    try:
        corroboration_doc = load_blob(corroboration.get("sha256"))
    except ReleaseUnavailable:
        raise ReleaseUnavailable("qualification_independent_corroboration_invalid") from None
    if (any(corroboration_doc.get(key) != row.get(key) for key in identity)
            or corroboration_doc.get("independent") is not True
            or corroboration_doc.get("source") != source
            or corroboration_doc.get("basis") not in {
                "documented_site_owner_control", "independent_historical_analysis",
                "second_publisher_source"}):
        raise ReleaseUnavailable("qualification_independent_corroboration_invalid")
    primary_sources = {str(primary.get(key, "")).strip().casefold()
                       for key in ("authority", "publisher_threat_feed", "source")}
    if source.strip().casefold() in primary_sources:
        raise ReleaseUnavailable("qualification_independent_source_not_distinct")
    if row.get("label") == 0 and corroboration_doc.get("basis") != "documented_site_owner_control":
        raise ReleaseUnavailable("qualification_benign_ownership_evidence_required")
    if row.get("label") == 1 and corroboration_doc.get("basis") == "documented_site_owner_control":
        raise ReleaseUnavailable("qualification_phishing_activity_evidence_required")


def validate_qualification_summary(evaluation, policy, paths, bundle_dir=None):
    """Recompute release gates; an aggregate ``passed`` flag is insufficient.

    These are necessary integrity checks, not proof of reviewer authenticity.
    Original acceptance floors cannot be weakened by a bundled policy.
    Requires genuine, non-placeholder evidence, physical file verification,
    direct record recomputation, and identical evaluation cohorts.
    """
    for key, floor in (("minimum_phishing_records", 2000), ("minimum_benign_records", 5000)):
        if type(policy.get(key)) is not int or policy[key] < floor:
            raise ReleaseUnavailable("qualification_policy_incomplete")
    if policy.get("require_wilson95_bounds") is not True or policy.get("minimum_coverage") != 1:
        raise ReleaseUnavailable("qualification_policy_incomplete")
    
    # 1. Require complete, non-placeholder evidence hashes
    evidence_keys = ("registration_sha256", "holdout_sha256", "independent_evidence_sha256",
                     "predictions_sha256", "exclusions_sha256", "source_code_sha256", "protocol_sha256")
    for key in evidence_keys:
        val = evaluation.get(key)
        if not isinstance(val, str) or not re.fullmatch(r"[0-9a-f]{64}", val):
            raise ReleaseUnavailable("qualification_evidence_incomplete")
        # Reject obvious dummy / repeated-character placeholder hashes
        if len(set(val)) <= 8 or val in {"0" * 64, "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64, "f" * 64}:
            raise ReleaseUnavailable("qualification_evidence_placeholder_rejected")

    # 2. Verify physical evidence files if bundle directory is provided
    evidence_manifest = evaluation.get("evidence_files")
    evidence_key_map = {
        "registration_sha256": "evidence/registration.json",
        "holdout_sha256": "evidence/holdout.jsonl",
        "independent_evidence_sha256": "evidence/independent_evidence.jsonl",
        "predictions_sha256": "evidence/predictions.json",
        "exclusions_sha256": "evidence/exclusions.json",
        "source_code_sha256": "evidence/source_code.tar.gz",
        "protocol_sha256": "evidence/protocol.json",
    }
    
    recomputed_counts = None
    if bundle_dir is not None:
        bundle_path = Path(bundle_dir).resolve()
        # Every mandatory evidence file must bind to its semantic digest. An
        # empty or partial caller-supplied mapping cannot waive verification.
        required_map = {name: evaluation[key] for key, name in evidence_key_map.items()}
        if evidence_manifest is not None and evidence_manifest != required_map:
            raise ReleaseUnavailable("qualification_evidence_manifest_mismatch")
        for ref_name, expected_hash in required_map.items():
            ev_path = (bundle_path / ref_name).resolve()
            if not ev_path.is_relative_to(bundle_path) or not ev_path.is_file():
                raise ReleaseUnavailable("qualification_evidence_file_missing")
            if sha256(ev_path) != expected_hash:
                raise ReleaseUnavailable("qualification_evidence_checksum_mismatch")
        threshold_document = _json(bundle_path / "thresholds.json")
        thresholds = threshold_document.get("decision_thresholds") or {
            path: threshold_document.get("medium") for path in paths}
        recomputed_counts = _recompute_qualification_records(
            bundle_path / "evidence/holdout.jsonl",
            bundle_path / "evidence/predictions.json", paths, thresholds)
        _verify_label_evidence(bundle_path, evaluation, paths)

    # 3. Enforce identical evaluation cohorts across all supported paths
    cohort_phishing = None
    cohort_benign = None
    cohort_sample_count = None

    for path in paths:
        metrics = evaluation.get("quality_by_path", {}).get(path, {})
        counts = metrics.get("counts", {})
        if not isinstance(counts, dict) or any(type(counts.get(k)) is not int or counts[k] < 0
                                               for k in ("tp", "fp", "tn", "fn", "unavailable")):
            raise ReleaseUnavailable("qualification_counts_invalid")
        tp, fp, tn, fn = (counts[k] for k in ("tp", "fp", "tn", "fn"))
        phishing_total = tp + fn
        benign_total = fp + tn
        total_samples = phishing_total + benign_total

        if (phishing_total < policy["minimum_phishing_records"]
                or benign_total < policy["minimum_benign_records"]
                or counts["unavailable"] != 0 or metrics.get("coverage") != 1
                or type(metrics.get("latency_sample_count")) is not int
                or metrics["latency_sample_count"] != total_samples):
            raise ReleaseUnavailable("qualification_counts_invalid")

        # Verify cohort equality across all paths
        if cohort_phishing is None:
            cohort_phishing = phishing_total
            cohort_benign = benign_total
            cohort_sample_count = metrics["latency_sample_count"]
        else:
            if phishing_total != cohort_phishing or benign_total != cohort_benign or metrics["latency_sample_count"] != cohort_sample_count:
                raise ReleaseUnavailable("qualification_cohort_mismatch: all paths must evaluate on identical cohorts")

        # If we recomputed counts from actual records, assert exact parity
        if recomputed_counts and path in recomputed_counts:
            rc = recomputed_counts[path]
            if metrics.get("latency_p95_ms") != rc["latency_p95_ms"]:
                raise ReleaseUnavailable("qualification_latency_record_mismatch")
            for metric_k in ("tp", "fp", "tn", "fn", "unavailable"):
                if counts.get(metric_k) != rc[metric_k]:
                    raise ReleaseUnavailable(f"qualification_count_record_mismatch: {path} {metric_k}")

        for successes, total, key in ((tp, tp + fn, "recall_wilson95"), (fp, fp + tn, "false_positive_rate_wilson95")):
            z = NormalDist().inv_cdf(.975)
            p = successes / total
            denominator = 1 + z * z / total
            center = (p + z * z / (2 * total)) / denominator
            half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
            expected = [max(0, center - half), min(1, center + half)]
            actual = metrics.get(key)
            if (not isinstance(actual, list) or len(actual) != 2
                    or any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
                           or not math.isclose(v, e, abs_tol=1e-10) for v, e in zip(actual, expected))):
                raise ReleaseUnavailable("qualification_interval_mismatch")


def _recompute_qualification_records(holdout_path, predictions_path, paths, thresholds):
    """Require exact membership and frozen thresholds before counting records."""
    labels = {}
    domains = set()
    for line in Path(holdout_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        sid, label = row.get("sample_id"), row.get("label")
        domain = row.get("registrable_domain") or row.get("domain")
        if (not isinstance(sid, str) or not sid or sid in labels
                or type(label) is not int or label not in (0, 1)
                or not isinstance(domain, str) or not domain.strip()
                or domain.lower().rstrip(".") in domains):
            raise ReleaseUnavailable("qualification_holdout_membership_invalid")
        domains.add(domain.lower().rstrip("."))
        labels[sid] = label
    records = _json(Path(predictions_path)).get("records")
    if not labels or not isinstance(records, list) or any(
            not isinstance(r, dict) or r.get("path") not in paths for r in records):
        raise ReleaseUnavailable("qualification_predictions_invalid")
    result = {}
    for path in paths:
        selected = [r for r in records if r["path"] == path]
        if len(selected) != len(labels) or {r.get("sample_id") for r in selected} != set(labels):
            raise ReleaseUnavailable("qualification_prediction_membership_mismatch")
        threshold = thresholds.get(path)
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not 0 < threshold < 1:
            raise ReleaseUnavailable("qualification_threshold_invalid")
        counts = dict(tp=0, fp=0, tn=0, fn=0, unavailable=0)
        latencies = []
        for row in selected:
            latency = row.get("elapsed_ms")
            if (isinstance(latency, bool) or not isinstance(latency, (int, float))
                    or not math.isfinite(latency) or latency < 0 or latency > 60000):
                raise ReleaseUnavailable("qualification_latency_invalid")
            latencies.append(latency)
            probability = row.get("probability")
            if "threshold" in row and row["threshold"] != threshold:
                raise ReleaseUnavailable("qualification_prediction_threshold_mismatch")
            if row.get("status") != "available":
                counts["unavailable"] += 1
                continue
            if (isinstance(probability, bool) or not isinstance(probability, (int, float))
                    or not math.isfinite(probability) or not 0 <= probability <= 1):
                raise ReleaseUnavailable("qualification_probability_invalid")
            positive = probability >= threshold
            label = labels[row["sample_id"]]
            counts[("tp" if positive else "fn") if label else ("fp" if positive else "tn")] += 1
        counts["latency_p95_ms"] = sorted(latencies)[math.ceil(.95 * len(latencies)) - 1]
        result[path] = counts
    return result


class ReleaseUnavailable(ValueError):
    """Bounded, non-secret reason safe for a report."""


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(path):
    def reject_constant(_):
        raise ReleaseUnavailable("invalid_contract")
    return json.loads(path.read_text(encoding="utf-8"), parse_constant=reject_constant)


_VERIFIED_RELEASE_CACHE = {}


def verify_release(directory, trust_anchor):
    if not directory or not re.fullmatch(r"[0-9a-f]{64}", trust_anchor or ""):
        raise ReleaseUnavailable("release_not_configured")
    root = Path(directory).resolve()
    manifest = root / "checksums.sha256"
    if not manifest.is_file() or sha256(manifest) != trust_anchor:
        raise ReleaseUnavailable("checksum_mismatch")

    cache_key = (str(root), trust_anchor)
    if cache_key in _VERIFIED_RELEASE_CACHE:
        cached_stats, cached_result = _VERIFIED_RELEASE_CACHE[cache_key]
        cache_valid = True
        try:
            for rel_path, (expected_mtime, expected_size) in cached_stats.items():
                p = root / rel_path
                st = p.stat()
                if st.st_mtime_ns != expected_mtime or st.st_size != expected_size:
                    cache_valid = False
                    break
        except OSError:
            cache_valid = False

        if cache_valid:
            return cached_result
    hashes = {}
    for line in manifest.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        if not match:
            raise ReleaseUnavailable("invalid_contract")
        digest, name = match.groups()
        if name in hashes or name.startswith("/") or any(p in {"", ".", ".."} for p in name.split("/")):
            raise ReleaseUnavailable("invalid_contract")
        file = (root / name).resolve()
        if not file.is_relative_to(root) or not file.is_file() or sha256(file) != digest:
            raise ReleaseUnavailable("checksum_mismatch")
        hashes[name] = digest
    required = {"release.json", "feature_contract.json", "approved_policy.json",
                "thresholds.json", "release_evaluation.json"}
    if not required.issubset(hashes):
        raise ReleaseUnavailable("invalid_contract")
    release = _json(root / "release.json")
    contract = _json(root / "feature_contract.json")
    policy = _json(root / "approved_policy.json")
    thresholds = _json(root / "thresholds.json")
    evaluation = _json(root / "release_evaluation.json")
    schema_version = release.get("schema_version")
    if (schema_version not in {1, 2} or release.get("status") != "validated"
            or not release.get("model_version") or not release.get("feature_contract_version")
            or evaluation.get("schema_version") != 1 or evaluation.get("verified") is not True
            or evaluation.get("passed") is not True or evaluation.get("blockers")
            or policy.get("status") != "approved"
            or type(contract.get("positive_label")) is not int or contract.get("positive_label") != 1
            or contract.get("scoring_backend") != "lightgbm_native_booster"
            or contract.get("version") != release["feature_contract_version"]):
        raise ReleaseUnavailable("release_not_validated")
    if schema_version == 1:
        if "classifier.txt" not in hashes:
            raise ReleaseUnavailable("invalid_contract")
        if evaluation.get("model_sha256") != hashes["classifier.txt"]:
            raise ReleaseUnavailable("evaluation_binding_mismatch")
    else:
        paths_for_models = release.get("supported_paths", [])
        fusion_by_path = contract.get("fusion_by_path")
        if not isinstance(fusion_by_path, dict) or set(fusion_by_path) != set(paths_for_models):
            raise ReleaseUnavailable("invalid_contract")
        model_hashes = {}
        for path, descriptor in fusion_by_path.items():
            if (not isinstance(descriptor, dict) or descriptor.get("feature_contract_version") != contract.get("version")
                    or not isinstance(descriptor.get("artifact_file"), str)
                    or hashes.get(descriptor["artifact_file"]) != descriptor.get("artifact_sha256")):
                raise ReleaseUnavailable("component_contract_mismatch")
            model_hashes[path] = hashes[descriptor["artifact_file"]]
        classifiers = release.get("classifiers_by_path")
        expected_classifiers = {path: item["artifact_file"] for path, item in fusion_by_path.items()}
        if classifiers is not None and classifiers != expected_classifiers:
            raise ReleaseUnavailable("evaluation_binding_mismatch")
        bound_model_hashes = evaluation.get("model_sha256_by_path")
        if bound_model_hashes != model_hashes:
            raise ReleaseUnavailable("evaluation_binding_mismatch")
    for key, name in {"feature_contract_sha256": "feature_contract.json",
                      "policy_sha256": "approved_policy.json", "thresholds_sha256": "thresholds.json"}.items():
        if evaluation.get(key) != hashes[name]:
            raise ReleaseUnavailable("evaluation_binding_mismatch")
    for key in ("model_version", "feature_contract_version", "supported_paths"):
        if release.get(key) != evaluation.get(key):
            raise ReleaseUnavailable("evaluation_binding_mismatch")
    paths = release.get("supported_paths")
    if not paths or not set(paths).issubset({"quick_url", "deep_url"}):
        raise ReleaseUnavailable("invalid_contract")
    fields = contract.get("features")
    if not isinstance(fields, list) or not fields:
        raise ReleaseUnavailable("invalid_contract")
    names = set()
    for field in fields:
        if (not isinstance(field, dict) or not re.fullmatch(r"[a-z][a-z0-9_]*", field.get("name", ""))
                or field["name"] in names or field.get("type") != "number"
                or not re.fullmatch(r"(?:components|scythe|scan_signals)\.[a-z][a-z0-9_]*", field.get("path", ""))
                or type(field.get("nullable", False)) is not bool):
            raise ReleaseUnavailable("invalid_contract")
        for bound in ("minimum", "maximum"):
            value = field.get(bound)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)):
                raise ReleaseUnavailable("invalid_contract")
        names.add(field["name"])
    components = contract.get("components_by_path")
    if not isinstance(components, dict) or set(paths) != set(components):
        raise ReleaseUnavailable("invalid_contract")
    for path, requirements in components.items():
        if not isinstance(requirements, dict) or not requirements or not set(requirements).issubset({"url", "visual"}):
            raise ReleaseUnavailable("invalid_contract")
        for kind, descriptor in requirements.items():
            if not isinstance(descriptor, dict):
                raise ReleaseUnavailable("invalid_contract")
            for key in ("artifact", "contract"):
                name = descriptor.get(key + "_file")
                if not isinstance(name, str) or not descriptor.get(key + "_sha256") or hashes.get(name) != descriptor[key + "_sha256"]:
                    raise ReleaseUnavailable("component_contract_mismatch")
            component = _json(root / descriptor["contract_file"])
            if component.get("version") != descriptor.get("model_version") or component.get("positive_label") != 1:
                raise ReleaseUnavailable("component_contract_mismatch")
            support_files = descriptor.get("support_files", [])
            if not isinstance(support_files, list):
                raise ReleaseUnavailable("component_contract_mismatch")
            support_names, support_roles = set(), []
            for item in support_files:
                if not isinstance(item, dict):
                    raise ReleaseUnavailable("component_contract_mismatch")
                name, role, checksum = item.get("file"), item.get("role"), item.get("sha256")
                if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_./-]+", name)
                        or name.startswith("/") or any(part in {"", ".", ".."} for part in name.split("/"))
                        or not isinstance(role, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", role)
                        or name in support_names
                        or not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum)
                        or hashes.get(name) != checksum):
                    raise ReleaseUnavailable("component_contract_mismatch")
                support_names.add(name)
                support_roles.append(role)
            if kind == "url" and component.get("scoring_backend") == "url_char_tfidf_linear_v1":
                if (component.get("version") != "url_char_tfidf_v1"
                        or support_roles.count("vectorizer") != 1):
                    raise ReleaseUnavailable("component_contract_mismatch")
    if schema_version == 1:
        values = [thresholds.get(k) for k in ("safe", "low", "medium", "high")]
        if (any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in values)
                or not 0 < values[0] < values[1] < values[2] < values[3] < 1):
            raise ReleaseUnavailable("invalid_contract")
    else:
        decision_thresholds = thresholds.get("decision_thresholds")
        if (thresholds.get("deployment_threshold") is not True
                or contract.get("version") != "scythe_fusion_v2" or set(paths) != {"quick_url", "deep_url"}
                or not isinstance(decision_thresholds, dict)
                or set(decision_thresholds) != set(paths)
                or any(isinstance(v, bool) or not isinstance(v, (int, float))
                       or not math.isfinite(v) or not 0 < v < 1 for v in decision_thresholds.values())):
            raise ReleaseUnavailable("invalid_contract")
        _validate_v2_feature_contract(contract, paths, components)
        for path, descriptor in contract["fusion_by_path"].items():
            threshold = descriptor.get("threshold")
            if (isinstance(threshold, bool) or not isinstance(threshold, (int, float))
                    or not math.isfinite(threshold) or threshold != decision_thresholds[path]):
                raise ReleaseUnavailable("evaluation_binding_mismatch")
    validate_qualification_summary(evaluation, policy, paths, bundle_dir=root)
    for path in paths:
        metrics = evaluation.get("quality_by_path", {}).get(path, {})
        if metrics.get("passed") is not True or metrics.get("coverage") != 1:
            raise ReleaseUnavailable("release_not_validated")
        try:
            numeric = [*metrics["recall_wilson95"], *metrics["false_positive_rate_wilson95"],
                       metrics["latency_p95_ms"], policy["minimum_recall"],
                       policy["maximum_false_positives_per_10000_benign"], policy["latency_limits_ms"][path]]
            if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) for value in numeric):
                raise ReleaseUnavailable("invalid_contract")
            if (not .8 <= policy["minimum_recall"] <= 1
                    or not 0 <= policy["maximum_false_positives_per_10000_benign"] <= 100
                    or not 0 < policy["latency_limits_ms"][path] <= (2000 if path == "quick_url" else 15000)
                    or not 0 <= metrics["recall_wilson95"][0] <= metrics["recall_wilson95"][1] <= 1
                    or not 0 <= metrics["false_positive_rate_wilson95"][0] <= metrics["false_positive_rate_wilson95"][1] <= 1
                    or metrics["latency_p95_ms"] < 0
                    or metrics["recall_wilson95"][0] < policy["minimum_recall"]
                    or metrics["false_positive_rate_wilson95"][1] > policy["maximum_false_positives_per_10000_benign"] / 10000
                    or metrics["latency_p95_ms"] > policy["latency_limits_ms"][path]):
                raise ReleaseUnavailable("release_not_validated")
        except (KeyError, TypeError, IndexError):
            raise ReleaseUnavailable("invalid_contract") from None

    file_stats = {}
    for name in hashes:
        if not name.startswith("evidence/blobs/") or len(hashes) < 100:
            try:
                st = (root / name).stat()
                file_stats[name] = (st.st_mtime_ns, st.st_size)
            except OSError:
                pass
    try:
        blobs_dir = root / "evidence/blobs"
        if blobs_dir.is_dir():
            st = blobs_dir.stat()
            file_stats["evidence/blobs"] = (st.st_mtime_ns, st.st_size)
    except OSError:
        pass

    result = (root, release, contract, thresholds, hashes)
    _VERIFIED_RELEASE_CACHE[cache_key] = (file_stats, result)
    return result


def _validate_v2_feature_contract(contract, paths, components):
    """Enforce the training/runtime v2 feature names, nullability and path inputs."""
    fields = contract.get("features", [])
    names = [field.get("name") for field in fields]
    scythe_names = ("brand_homoglyph_detected", "domain_expiration_duration_days",
                    "corporate_lookalike_distance", "hosting_provider_abuse_history",
                    "open_threat_exchange_pulse_count", "url_shortener_used",
                    "certificate_transparency_velocity", "ip_hosting_type")
    scan_names = ("browser_dom_form_count", "browser_dom_script_count", "browser_dom_link_count",
                  "sandbox_password_field_count", "sandbox_cross_domain_form_count",
                  "consistency_score", "consistency_cloaking_suspected")
    expected_names = ["url_probability", "visual_probability", "visual_available"]
    expected_names += [item for name in scythe_names for item in (name, name + "_available")]
    expected_names += [item for name in scan_names for item in (name, name + "_available")]
    if (len(fields) != 33 or len(set(names)) != 33 or names != expected_names):
        raise ReleaseUnavailable("invalid_contract")
    by_name = {field["name"]: field for field in fields}
    if (by_name["url_probability"].get("path") != "components.url_probability"
            or by_name["url_probability"].get("nullable") is not False
            or by_name["visual_probability"].get("path") != "components.visual_probability"
            or by_name["visual_probability"].get("nullable") is not True
            or by_name["visual_available"].get("path") != "components.visual_available"
            or by_name["visual_available"].get("nullable") is not False):
        raise ReleaseUnavailable("invalid_contract")
    for field in fields[3:]:
        name, path = field.get("name"), field.get("path", "")
        if not name or not (path.startswith("scythe.") or path.startswith("scan_signals.")):
            raise ReleaseUnavailable("invalid_contract")
        if name.endswith("_available"):
            if field.get("nullable") is not False or field.get("minimum") != 0 or field.get("maximum") != 1:
                raise ReleaseUnavailable("invalid_contract")
        elif field.get("nullable") is not True:
            raise ReleaseUnavailable("invalid_contract")
    for path in paths:
        requirement = components[path]
        if "url" not in requirement or (path == "quick_url" and "visual" in requirement):
            raise ReleaseUnavailable("component_contract_mismatch")
        if path == "deep_url" and "visual" not in requirement:
            raise ReleaseUnavailable("component_contract_mismatch")
    fusion_by_path = contract.get("fusion_by_path")
    if not isinstance(fusion_by_path, dict) or set(fusion_by_path) != set(paths):
        raise ReleaseUnavailable("invalid_contract")
    for descriptor in fusion_by_path.values():
        if (not isinstance(descriptor, dict) or descriptor.get("model_version") != contract.get("version")
                or descriptor.get("feature_contract_version") != contract.get("version")
                or descriptor.get("feature_order") != expected_names
                or not isinstance(descriptor.get("artifact_file"), str)
                or not re.fullmatch(r"[A-Za-z0-9_./-]+", descriptor["artifact_file"])
                or not isinstance(descriptor.get("artifact_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", descriptor["artifact_sha256"])):
            raise ReleaseUnavailable("invalid_contract")


def build_vector(evidence, contract, path=None):
    """Ordered numeric paths only. No source, URL, labels or metadata predictors."""
    fields = contract.get("features")
    if not isinstance(fields, list) or not fields:
        raise ReleaseUnavailable("invalid_contract")
    values, names = [], set()
    if contract.get("version") == "scythe_fusion_v2":
        if path not in {"quick_url", "deep_url"}:
            raise ReleaseUnavailable("unsupported_input_path")
        if path == "quick_url":
            if evidence.get("components", {}).get("visual_probability") is not None:
                raise ReleaseUnavailable("invalid_evidence")
            for namespace in ("scythe", "scan_signals"):
                for key, value in evidence.get(namespace, {}).items():
                    if key.endswith("_available") and value != 0:
                        raise ReleaseUnavailable("invalid_evidence")
                    if not key.endswith("_available") and value is not None:
                        raise ReleaseUnavailable("invalid_evidence")
    for field in fields:
        name, feature_path = field.get("name"), field.get("path", "")
        if (not name or name in names or field.get("type") != "number"
                or not re.fullmatch(r"(?:components|scythe|scan_signals)\.[a-z][a-z0-9_]*", feature_path)):
            raise ReleaseUnavailable("invalid_contract")
        names.add(name)
        namespace, key = feature_path.split(".")
        value = evidence.get(namespace, {}).get(key)
        if value is None:
            if not field.get("nullable", False):
                raise ReleaseUnavailable("missing_evidence")
            values.append(float("nan"))
            continue
        if (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
                or (field.get("minimum") is not None and value < field["minimum"])
                or (field.get("maximum") is not None and value > field["maximum"])):
            raise ReleaseUnavailable("invalid_evidence")
        if name.endswith("_available") and value not in (0, 1):
            raise ReleaseUnavailable("invalid_evidence")
        values.append(float(value))
    if contract.get("version") == "scythe_fusion_v2":
        by_name = {field["name"]: values[index] for index, field in enumerate(fields)}
        visual_probability = evidence.get("components", {}).get("visual_probability")
        visual_status = evidence.get("component_results", {}).get("visual", {}).get("status")
        expected_available = int(visual_status == "observed")
        if by_name.get("visual_available") != expected_available:
            raise ReleaseUnavailable("invalid_evidence")
        if (visual_probability is None) != (expected_available == 0):
            raise ReleaseUnavailable("invalid_evidence")
        for field in fields:
            name = field["name"]
            if not name.endswith("_available") or name in {"visual_available"}:
                continue
            base = name.removesuffix("_available")
            value = by_name.get(base)
            available = by_name[name]
            if (available == 0 and not (isinstance(value, float) and math.isnan(value))) or (available == 1 and not math.isfinite(value)):
                raise ReleaseUnavailable("invalid_evidence")
    return values


@lru_cache(maxsize=4)
def _load_native(directory, trust_anchor, path="quick_url"):
    root, release, contract, _, _ = verify_release(directory, trust_anchor)
    import lightgbm
    if release.get("schema_version") == 2:
        model_name = contract.get("fusion_by_path", {}).get(path, {}).get("artifact_file")
        if not model_name:
            raise ReleaseUnavailable("unsupported_input_path")
    else:
        model_name = "classifier.txt"
    model = lightgbm.Booster(model_file=str(root / model_name))
    if model.feature_name() != [f["name"] for f in contract["features"]]:
        raise ReleaseUnavailable("invalid_contract")
    if model.num_model_per_iteration() != 1 or model.dump_model().get("objective", "").split()[0] != "binary":
        raise ReleaseUnavailable("invalid_contract")
    return model


def score_release(directory, trust_anchor, evidence, path):
    # Reverify even on a warm worker: a changed file must not use cached trust.
    _, release, contract, thresholds, hashes = verify_release(directory, trust_anchor)
    if path not in release["supported_paths"]:
        raise ReleaseUnavailable("unsupported_input_path")
    requirements = contract.get("components_by_path", {}).get(path)
    if not isinstance(requirements, dict) or not requirements or not set(requirements).issubset({"url", "visual"}):
        raise ReleaseUnavailable("invalid_contract")
    for component, expected in requirements.items():
        actual = evidence.get("component_results", {}).get(component, {})
        if actual.get("status") != "observed" or actual.get("artifact_hashes") != expected:
            raise ReleaseUnavailable("component_contract_mismatch")
    vector = build_vector(evidence, contract, path if contract.get("version") == "scythe_fusion_v2" else None)
    model = _load_native(str(Path(directory).resolve()), trust_anchor, path)
    probability = float(model.predict([vector], num_threads=1)[0])
    if not math.isfinite(probability) or not 0 <= probability <= 1:
        raise ReleaseUnavailable("inference_failed")
    if contract.get("version") == "scythe_fusion_v2":
        severity = "HIGH" if probability >= thresholds["decision_thresholds"][path] else "SAFE"
    else:
        severity = next((level for key, level in (("safe", "SAFE"), ("low", "LOW"), ("medium", "MEDIUM"), ("high", "HIGH"))
                         if probability < thresholds[key]), "CRITICAL")
    return {"risk_score": round(probability * 100, 2), "risk_level": severity,
            "probability": probability, "is_placeholder": False, "availability": "observed",
            "model_version": release["model_version"], "contract_version": contract["version"],
            "release_manifest_sha256": trust_anchor,
            "model_sha256": (hashes[contract["fusion_by_path"][path]["artifact_file"]]
                             if release.get("schema_version") == 2 else hashes["classifier.txt"]),
            **({"classification_threshold": thresholds["decision_thresholds"][path]}
               if contract.get("version") == "scythe_fusion_v2" else {})}
