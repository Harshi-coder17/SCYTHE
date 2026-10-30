"""Fail-closed research-model release evidence audit; does not deserialize models.

Exit 0 only when every production gate passes. Current research bundles should
exit 2 with a useful report. This command never trains, selects, or activates.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from datetime import datetime, timezone


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def validate_workspace(directory):
    """Reject a repository directory mistaken for the dataset workspace."""
    directory = Path(directory).resolve()
    required = ("SCYTHE", "lightgbm_dataset", "mobileclip-dataset")
    missing = [name for name in required if not (directory / name).is_dir()]
    if missing:
        raise ValueError(
            f"Workspace {directory} is missing top-level directories: {', '.join(missing)}. "
            "Pass --workspace pointing to the parent containing SCYTHE and both dataset directories."
        )
    return directory


def verify_bundle(directory):
    directory = Path(directory).resolve()
    manifest = directory / "checksums.sha256"
    problems, verified = [], 0
    if not manifest.is_file():
        return {"valid": False, "verified_files": 0, "errors": ["missing checksums.sha256"]}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        if not re.match(r"^[a-fA-F0-9]{64}  .+", line):
            problems.append("invalid checksum entry")
            continue
        expected, name = line.split("  ", 1)
        path = (directory / name).resolve()
        if not path.is_relative_to(directory) or path == directory:
            problems.append("checksum path escapes bundle")
        elif not path.is_file():
            problems.append(f"missing {name}")
        elif sha256(path) != expected.lower():
            problems.append(f"checksum mismatch: {name}")
        else:
            verified += 1
    if not verified:
        problems.append("no verified artifacts")
    return {"valid": not problems, "verified_files": verified, "errors": problems,
            "checksum_manifest_sha256": sha256(manifest)}


def policy_errors(policy):
    errors = []
    if policy.get("status") != "approved" or not policy.get("approved_by") or not policy.get("approved_at_utc"):
        errors.append("Operational policy needs explicit owner approval")
    for key, lower, upper in [("maximum_false_positives_per_10000_benign", 0, 10000),
                              ("minimum_recall", 0, 1), ("maximum_p95_latency_ms", 0, None)]:
        value = policy.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < lower or (upper is not None and value > upper):
            errors.append(f"Policy value is required: {key}")
    if not policy.get("intended_population") or not policy.get("failure_behavior"):
        errors.append("Policy must define intended population and unavailable-input behavior")
    return errors


def inspect_holdouts(root):
    base = root / "lightgbm_dataset/fresh/external_holdouts"
    registry = read_json(base / "registry.json")
    rows = []
    for run_id, item in registry.get("runs", {}).items():
        path = base / run_id / "registration.json"
        registration = read_json(path)
        verified = path.is_file() and sha256(path) == item.get("registration_sha256")
        evidence = base / run_id / "independent_label_evidence.csv"
        evidence_verified = (evidence.is_file() and sha256(evidence) == registration.get("independent_evidence_sha256"))
        qualified = (verified and evidence_verified and item.get("status") == "untouched_external_holdout"
                     and registration.get("status") == "untouched_external_holdout"
                     and registration.get("operator_attested_model_metrics_uninspected") is True
                     and registration.get("independent_evidence_coverage") == 1
                     and registration.get("independent_evidence_label_matches") is True
                     and registration.get("existing_domain_overlap_count") == 0)
        rows.append({"run_id": run_id, "status": item.get("status"), "registration_hash_verified": verified, "independent_evidence_hash_verified": evidence_verified,
                     "qualified_untouched": qualified, "records": registration.get("record_count"),
                     "independent_label_evidence_coverage": registration.get("independent_evidence_coverage"),
                     "overlap_domains": registration.get("existing_domain_overlap_count")})
    return rows


def inspect_training_exclusions(root):
    try:
        import pyarrow.parquet as pq
    except ImportError:
        return {"status": "unverified", "reason": "pyarrow unavailable; use --dataset-deps with existing trusted research environment"}
    directory = root / "lightgbm_dataset/fresh/dataset_dev_v2"
    registry = root / "lightgbm_dataset/exclusions/url_candidate_v1"
    try:
        urls = set((registry / "canonical_urls.txt").read_text(encoding="utf-8").splitlines())
        domains = set((registry / "registrable_domains.txt").read_text(encoding="utf-8").splitlines())
        counts = {}
        split_domains = {}
        for split in ("train", "validation"):
            table = pq.read_table(directory / f"{split}.parquet", columns=["url", "registrable_domain"])
            rows = table.to_pylist()
            counts[split] = {"rows": len(rows), "excluded_url_hits": sum(row["url"] in urls for row in rows),
                             "excluded_domain_hits": sum(row["registrable_domain"] in domains for row in rows)}
            split_domains[split] = {row["registrable_domain"] for row in rows}
        overlap = len(split_domains["train"] & split_domains["validation"])
        valid = not overlap and all(not row["excluded_url_hits"] and not row["excluded_domain_hits"] for row in counts.values())
        return {"status": "verified" if valid else "failed", "counts": counts, "cross_split_domain_overlap": overlap,
                "scope": "Frozen candidate-time exclusions; newly registered development datasets cannot retrospectively become its untouched test"}
    except (OSError, KeyError) as exc:
        return {"status": "unverified", "reason": type(exc).__name__}


def inspect_release_bundle(directory, expected_checksums_sha256=None):
    """Inspect an explicitly trusted release; legacy research status cannot pass."""
    directory = Path(directory).resolve()
    checks = verify_bundle(directory)
    errors = list(checks["errors"])
    if not expected_checksums_sha256 or checks.get("checksum_manifest_sha256") != expected_checksums_sha256:
        errors.append("Release checksum manifest requires a matching configured trust anchor")
    manifest = read_json(directory / "release.json")
    evaluation = read_json(directory / "release_evaluation.json")
    policy = read_json(directory / "approved_policy.json")
    errors.extend(policy_errors(policy))
    schema_version = manifest.get("schema_version")
    if schema_version not in (1, 2) or manifest.get("status") != "validated":
        errors.append("Release manifest is not validated schema v1/v2")
    if evaluation.get("schema_version") != 1 or evaluation.get("passed") is not True or evaluation.get("verified") is not True:
        errors.append("Release evaluation did not pass independently verified gates")
    required = {"release.json", "release_evaluation.json", "feature_contract.json", "approved_policy.json", "thresholds.json"}
    if schema_version == 1:
        required.add("classifier.txt")
    else:
        for path_name in manifest.get("supported_paths", []):
            req_file = manifest.get("classifiers_by_path", {}).get(path_name)
            if req_file:
                required.add(req_file)
    checksum_entries = set()
    checksum_path = directory / "checksums.sha256"
    if checksum_path.is_file():
        checksum_entries = {line.split("  ", 1)[1] for line in checksum_path.read_text().splitlines() if "  " in line}
    if not required <= checksum_entries:
        errors.append("Release checksum manifest omits required files")
    for file, key in (("feature_contract.json", "feature_contract_sha256"),
                      ("approved_policy.json", "policy_sha256"), ("thresholds.json", "thresholds_sha256")): 
        target = directory / file
        if not target.is_file() or sha256(target) != evaluation.get(key):
            errors.append("Release evidence binding mismatch: " + key)
    if schema_version == 1:
        if not (directory / "classifier.txt").is_file() or sha256(directory / "classifier.txt") != evaluation.get("model_sha256"):
            errors.append("Release evidence binding mismatch: model_sha256")
    for key in ("model_version", "feature_contract_version", "supported_paths"):
        if not manifest.get(key) or manifest.get(key) != evaluation.get(key):
            errors.append("Release/evaluation identity mismatch: " + key)
    def number(value, lower=0, upper=None):
        return (not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value)
                and value >= lower and (upper is None or value <= upper))

    if not set(manifest.get("supported_paths", [])) <= {"quick_url", "deep_url"}:
        errors.append("Release has unsupported scoring paths")
    for path in manifest.get("supported_paths", []):
        metrics = evaluation.get("quality_by_path", {}).get(path, {})
        recall = metrics.get("recall_wilson95", [None, None])
        fpr = metrics.get("false_positive_rate_wilson95", [None, None])
        latency = metrics.get("latency_p95_ms")
        budget = policy.get("latency_limits_ms", {}).get(path)
        if (metrics.get("passed") is not True or metrics.get("coverage") != 1
                or not isinstance(recall, list) or len(recall) != 2 or not number(recall[0], .8, 1)
                or not isinstance(fpr, list) or len(fpr) != 2 or not number(fpr[1], 0, .01)
                or not number(latency) or not number(budget) or latency > budget):
            errors.append("Release path quality/coverage/latency evidence failed: " + path)
    # Reuse the runtime verifier so readiness cannot accept weaker summary gates.
    import importlib.util
    source = Path(__file__).resolve().parents[1] / "containers/backend/services/model_release.py"
    spec = importlib.util.spec_from_file_location("release_qualification_verifier", source)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    try:
        verifier.validate_qualification_summary(evaluation, policy, manifest.get("supported_paths", []), bundle_dir=directory)
    except (ValueError, TypeError, KeyError) as exc:
        errors.append("Release qualification failed: " + str(exc))
    return {"verified": not errors, "errors": errors, "hashes": checks,
            "model_version": manifest.get("model_version"), "evaluation": evaluation}


def inspect_additional_candidates(root):
    """Report completed new experiments without treating them as releases."""
    candidates = []
    collection = root / "lightgbm_dataset/prospective_collection_v1"
    census_path = collection / "v1_conflict_census.json"
    census = read_json(census_path)
    directories = list(collection.glob("url_candidate_v*"))
    directories += list((root / "lightgbm_dataset").glob("prospective_reviewed_dev_v*_fusion_v2"))
    url_artifacts = root / "lightgbm_dataset/fresh/artifacts"
    directories += list(url_artifacts.glob("url_character_dev_*"))
    directories += list(url_artifacts.glob("lightgbm_multisource_url_dev_*"))
    artifacts = root / "mobileclip-dataset/artifacts"
    directories += list(artifacts.glob("zenodo_url_dev_v*"))
    directories += [p for p in artifacts.glob("mobileclip_v*")
                    if re.fullmatch(r"mobileclip_v[0-9]+", p.name) and int(p.name.removeprefix("mobileclip_v")) >= 3]
    for directory in sorted({p.resolve() for p in directories if p.is_dir() and (p / "run_manifest.json").is_file()}):
        manifest = read_json(directory / "run_manifest.json")
        superseded = (directory.name == "url_candidate_v1"
                      and census.get("status") == "superseded_experimental_candidate_do_not_promote")
        candidates.append({"path": directory.relative_to(root).as_posix(),
                           "version": manifest.get("version", directory.name),
                           "status": "superseded_do_not_promote" if superseded else manifest.get("status"),
                           "hashes": verify_bundle(directory),
                           "contract": read_json(directory / "feature_contract.json"),
                           "validation_metrics": read_json(directory / "metrics_validation.json"),
                           "release_approved": False,
                           "supersession_evidence_sha256": sha256(census_path) if superseded else None})
    return candidates


def build_report(root, policy=None, release_bundle=None, release_checksums_sha256=None):
    root = Path(root).resolve()
    directories = {
        "lightgbm_dev_v2": "lightgbm_dataset/fresh/artifacts/lightgbm_dev_v2",
        "mobileclip_v1": "mobileclip-dataset/artifacts/mobileclip_v1",
        "mobileclip_v2": "mobileclip-dataset/artifacts/mobileclip_v2",
    }
    bundles = {}
    for name, relative in directories.items():
        directory = root / relative
        contract = read_json(directory / "feature_contract.json")
        if name.startswith("lightgbm"):
            helper = root / "SCYTHE/containers/backend/services/model_features/url_features.py"
            expected_features = None
            if helper.is_file():
                for node in ast.parse(helper.read_text(encoding="utf-8")).body:
                    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "FEATURE_NAMES" for target in node.targets):
                        expected_features = list(ast.literal_eval(node.value))
            expected = contract.get("features") == expected_features and expected_features is not None
        else:
            encoder = read_json(directory / "encoder_ref.json")
            embedding_valid = (contract.get("embedding_dimensions") == 512 and contract.get("embedding_normalization") == "L2")
            # Frozen v1's legacy contract expresses dimension/normalization as
            # a literal string, independently corroborated by encoder metadata.
            if name == "mobileclip_v1":
                embedding_valid = contract.get("embedding") == "512 float32 values, L2-normalized" and encoder.get("embedding_dimensions") == 512
            expected = embedding_valid and contract.get("class_order") == [0, 1] and contract.get("missing_input") == "unavailable"
        bundles[name] = {"path": relative, "hashes": verify_bundle(directory),
                         "contract_valid": bool(expected and contract.get("positive_label") == 1),
                         "status": read_json(directory / "run_manifest.json").get("status"),
                         "validation_metrics": read_json(directory / "metrics_validation.json")}
    holdouts = inspect_holdouts(root)
    exclusions = inspect_training_exclusions(root)
    comparison = read_json(root / "mobileclip-dataset/artifacts/mobileclip_v2_external_comparison_v1/comparison.json")
    enrichment = read_json(root / "lightgbm_dataset/fresh/enrichment_pilot_v2/enrichment_report.json")
    blockers = policy_errors(policy or {})
    if not all(bundle["hashes"]["valid"] and bundle["contract_valid"] for bundle in bundles.values()):
        blockers.append("One or more frozen bundle hashes/contracts failed verification")
    if exclusions.get("status") != "verified":
        blockers.append("Candidate exclusion/domain split verification did not pass")
    if not any(item["qualified_untouched"] for item in holdouts):
        blockers.append("No registered independently labeled, domain-disjoint, genuinely untouched holdout is available")
    # Existing models are deliberately experimental. No checked report can
    # promote them merely because a policy file or health endpoint exists.
    blockers.append("No immutable release evaluation binds approved policy, frozen model/contract hashes, untouched data, and production latency")
    blockers.append("No validated final risk-fusion release bundle was supplied; implemented loaders alone cannot certify model quality")
    metrics = {name: {"raw": data.get("raw_metrics"), "sampling_weighted": data.get("sampling_weighted_metrics")}
               for name, data in comparison.get("versions", {}).items()}
    release = inspect_release_bundle(release_bundle, release_checksums_sha256) if release_bundle else None
    # A new release has its own immutable exclusion/evaluation evidence. Legacy
    # research bundles remain diagnostic and cannot veto or certify that release.
    if release is not None:
        blockers = release["errors"]
    return {"schema_version": "model_release_readiness_v1", "workspace": str(root), "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "production_ready": bool(release and release["verified"]), "release": release,
            "research_artifacts_verified": all(b["hashes"]["valid"] for b in bundles.values()),
            "bundles": bundles, "additional_experimental_candidates": inspect_additional_candidates(root),
            "training_exclusions": exclusions, "registered_holdouts": holdouts,
            "inspected_external_visual_development_metrics": metrics,
            "paired_comparison": comparison.get("paired_comparison", {}),
            "inspected_external_url_development_metrics": {
                "model": read_json(root / "lightgbm_dataset/fresh/external_evaluations/phishvn_v4/metrics.json").get("model"),
                "metrics": read_json(root / "lightgbm_dataset/fresh/external_evaluations/phishvn_v4/metrics.json").get("metrics", {}).get("overall"),
                "role": "Already inspected lightgbm_fresh_v2 development failure, not an untouched evaluation of lightgbm_dev_v2"},
            "latency_evidence": {"encoder_extraction_benchmark": read_json(root / "mobileclip-dataset/artifacts/mobileclip_v1/benchmark.json"),
                                 "limitation": "Batch extraction throughput does not establish production request p95 latency"},
            "enrichment": {"cohort": enrichment.get("cohort"), "feature_status_counts": enrichment.get("feature_status_counts"),
                           "provider_policy": enrichment.get("provider_policy"), "limitations": enrichment.get("diagnostic_limits")},
            "blockers": blockers, "actions": (["Record owner-approved operational policy before evaluation"] if policy_errors(policy or {}) else []) + [
                "Register a new source/capture manifest with historical independent labels, evidence checksums and domain exclusions",
                "Freeze candidates and protocol before scoring; evaluate once and archive failure as well as success",
                "Collect prospective enrichment with source timestamps and licensed provider access; retrospective values remain diagnostic",
                "Obtain independently supported benign controls; Tranco rank alone does not confirm a benign label"],
            "limitations": ["Previously examined PhishVN/Phish360/visual external sets are development benchmarks",
                            "Unknown screenshot domains prevent complete overlap verification; campaigns remain unverified",
                            "No training, scoring, model deserialization, threshold selection or activation occurs in this command"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--dataset-deps", type=Path, help="Existing trusted environment containing pyarrow")
    parser.add_argument("--release-bundle", type=Path, help="Explicit local release directory, distinct from research bundles")
    parser.add_argument("--release-checksums-sha256", help="Previously recorded trust anchor, not derived implicitly from the bundle")
    args = parser.parse_args()
    try:
        args.workspace = validate_workspace(args.workspace)
    except ValueError as exc:
        parser.error(str(exc))
    if args.dataset_deps:
        sys.path.insert(0, str(args.dataset_deps.resolve()))
    report = build_report(args.workspace, read_json(args.policy) if args.policy else None,
                          args.release_bundle, args.release_checksums_sha256)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"production_ready": report["production_ready"], "blocker_count": len(report["blockers"]),
                      "report": str(args.output.resolve())}))
    return 0 if report["production_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
