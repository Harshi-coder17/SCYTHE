"""Stage and verify an evaluated local model release, then finalize atomically.

This packages evidence; it never trains, selects thresholds, or enables inference.
Both final and staging paths must be absent. Failed staging remains for review.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_candidate(directory, trust_anchor):
    root = Path(directory).resolve()
    manifest = root / "checksums.sha256"
    if not re.fullmatch(r"[0-9a-f]{64}", trust_anchor or "") or not manifest.is_file() or sha256(manifest) != trust_anchor:
        raise ValueError("candidate checksum trust anchor mismatch")
    files = {}
    for line in manifest.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        if not match:
            raise ValueError("invalid candidate checksum entry")
        digest, name = match.groups()
        file = (root / name).resolve()
        if (name in files or name.startswith("/") or any(part in {"", ".", ".."} for part in name.split("/"))
                or not file.is_relative_to(root) or not file.is_file() or sha256(file) != digest):
            raise ValueError("candidate path or checksum failed")
        files[name] = (file, digest)
    if "feature_contract.json" not in files:
        raise ValueError("candidate feature contract required")
    return files


def runtime_module():
    source = Path(__file__).resolve().parents[1] / "containers/backend/services/model_release.py"
    spec = importlib.util.spec_from_file_location("scythe_release_verifier", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_component_bindings(candidate_contract, files):
    """Require every component payload and auxiliary file to be in the candidate manifest."""
    components_by_path = candidate_contract.get("components_by_path")
    if not isinstance(components_by_path, dict) or not components_by_path:
        raise ValueError("candidate component descriptors required")
    for requirements in components_by_path.values():
        if not isinstance(requirements, dict) or not requirements:
            raise ValueError("candidate component descriptors invalid")
        for descriptor in requirements.values():
            if not isinstance(descriptor, dict):
                raise ValueError("candidate component descriptor invalid")
            for stem in ("artifact", "contract"):
                name, checksum = descriptor.get(stem + "_file"), descriptor.get(stem + "_sha256")
                if not isinstance(name, str) or not checksum or files.get(name, (None, None))[1] != checksum:
                    raise ValueError("candidate component file is not checksum-bound: " + stem)
            support_files = descriptor.get("support_files", [])
            if not isinstance(support_files, list):
                raise ValueError("candidate support_files must be a list")
            seen = set()
            for item in support_files:
                if not isinstance(item, dict):
                    raise ValueError("candidate support file descriptor invalid")
                name, checksum = item.get("file"), item.get("sha256")
                if (not isinstance(name, str) or name in seen or not item.get("role")
                        or not checksum or files.get(name, (None, None))[1] != checksum):
                    raise ValueError("candidate support file is not checksum-bound")
                seen.add(name)


def build_release(candidate_dir, candidate_checksums_sha256, evaluation_path, policy_path, thresholds_path, output):
    output = Path(output).resolve()
    staging = output.with_name(output.name + ".staging")
    if output.exists() or staging.exists():
        raise FileExistsError("release or staging version already exists")
    files = verify_candidate(candidate_dir, candidate_checksums_sha256)
    candidate_contract = read_json(files["feature_contract.json"][0])
    evaluation = read_json(evaluation_path)
    if (evaluation.get("schema_version") != 1 or evaluation.get("passed") is not True
            or evaluation.get("verified") is not True or evaluation.get("blockers")):
        raise ValueError("release evaluation has not passed")
    common_bindings = [(files["feature_contract.json"][0], "feature_contract_sha256"),
                       (policy_path, "policy_sha256"), (thresholds_path, "thresholds_sha256")]
    schema_version = 1
    classifiers_by_path = None
    if candidate_contract.get("version") == "scythe_fusion_v2":
        schema_version = 2
        threshold_document = read_json(thresholds_path)
        decision_thresholds = threshold_document.get("decision_thresholds")
        if threshold_document.get("deployment_threshold") is not True:
            raise ValueError("qualified path-specific deployment thresholds required")
        fusion_by_path = candidate_contract.get("fusion_by_path")
        if not isinstance(fusion_by_path, dict) or set(fusion_by_path) != set(evaluation.get("supported_paths", [])):
            raise ValueError("v2 candidate requires a fusion artifact for every evaluated path")
        if (not isinstance(decision_thresholds, dict) or set(decision_thresholds) != set(fusion_by_path)
                or threshold_document.get("deployment_threshold") is not True):
            raise ValueError("qualified path-specific deployment thresholds required")
        validate_component_bindings(candidate_contract, files)
        classifiers_by_path = {}
        expected_hashes = {}
        for path, descriptor in fusion_by_path.items():
            if (not isinstance(descriptor, dict) or not isinstance(descriptor.get("artifact_file"), str)
                    or descriptor.get("feature_contract_version") != candidate_contract.get("version")
                    or descriptor.get("artifact_sha256") != files.get(descriptor["artifact_file"], (None, None))[1]
                    or descriptor.get("threshold") != decision_thresholds.get(path)):
                raise ValueError("v2 fusion artifact or threshold binding mismatch")
            classifiers_by_path[path] = descriptor["artifact_file"]
            expected_hashes[path] = descriptor["artifact_sha256"]
        if evaluation.get("model_sha256_by_path") != expected_hashes:
            raise ValueError("evaluation must bind both path-specific fusion artifacts")
    else:
        if "classifier.txt" not in files:
            raise ValueError("candidate model artifact required")
        common_bindings.insert(0, (files["classifier.txt"][0], "model_sha256"))
    for file, key in common_bindings:
        if sha256(file) != evaluation.get(key):
            raise ValueError("evaluation input binding mismatch: " + key)
    reserved = {"release.json", "release_evaluation.json", "approved_policy.json", "thresholds.json", "checksums.sha256"}
    staging.mkdir(parents=True, exist_ok=False)
    for name, (file, expected_digest) in files.items():
        if name in reserved:
            continue
        target = staging / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, target)
        if sha256(target) != expected_digest:
            raise ValueError("candidate changed during staging")
    for file, name in ((evaluation_path, "release_evaluation.json"), (policy_path, "approved_policy.json"), (thresholds_path, "thresholds.json")):
        shutil.copyfile(file, staging / name)
    # Evaluation evidence accompanies its report and is copied immutably into
    # the release; runtime verification checks each semantic digest below.
    evidence_root = Path(evaluation_path).resolve().parent
    for name in ("registration.json", "holdout.jsonl", "independent_evidence.jsonl",
                 "predictions.json", "exclusions.json", "source_code.tar.gz", "protocol.json"):
        source = evidence_root / "evidence" / name
        if not source.is_file():
            source = Path(candidate_dir).resolve() / "evidence" / name
        if not source.is_file():
            raise ValueError("missing packaged qualification evidence: " + name)
        target = staging / "evidence" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    dependency_dir = evidence_root / "evidence"
    for source in dependency_dir.rglob("*"):
        if source.is_file() and (source.parent.name == "blobs" or source.name == "dependency_index.json"):
            target = staging / "evidence" / source.relative_to(dependency_dir)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    manifest = {"schema_version": schema_version, "status": "validated",
                "model_version": evaluation.get("model_version"),
                "feature_contract_version": evaluation.get("feature_contract_version"),
                "supported_paths": evaluation.get("supported_paths"),
                "allowed_actions": read_json(policy_path).get("allowed_actions", []),
                "evaluation_file": "release_evaluation.json",
                "candidate_checksums_sha256": candidate_checksums_sha256,
                "created_at_utc": datetime.now(timezone.utc).isoformat()}
    if schema_version == 2:
        manifest["classifiers_by_path"] = classifiers_by_path
    (staging / "release.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum_lines = [f"{sha256(file)}  {file.relative_to(staging).as_posix()}\n"
                      for file in sorted(staging.rglob("*")) if file.is_file()]
    checksums = staging / "checksums.sha256"
    checksums.write_text("".join(checksum_lines), encoding="ascii")
    anchor = sha256(checksums)
    runtime_module().verify_release(str(staging), anchor)
    # Atomic same-filesystem directory rename; never merge with another version.
    staging.rename(output)
    return {"release": str(output), "checksums_sha256": anchor, "model_version": manifest["model_version"],
            "enabled": False, "status": "packaged_verified_not_activated"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--candidate-checksums-sha256", required=True)
    parser.add_argument("--evaluation", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--thresholds", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_release(args.candidate_dir, args.candidate_checksums_sha256, args.evaluation,
                               args.policy, args.thresholds, args.output)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"status": "failed", "enabled": False, "error": str(exc)}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
