"""Measure an experimental paired candidate; creates no release evidence claim."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import shutil
import sys
import time
from types import SimpleNamespace

STARTED = time.perf_counter()
WORKSPACE = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(WORKSPACE / "lightgbm_dataset/_deps"), str(WORKSPACE / "lightgbm_dataset"),
                str(WORKSPACE / "SCYTHE/containers/backend"), str(Path(__file__).resolve().parent)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--warm-scores-per-path", type=int, default=32)
    parser.add_argument("--workload-note", default="Concurrent development workloads were not controlled; timings are host-load dependent")
    args = parser.parse_args()
    if args.warm_scores_per_path < 30:
        parser.error("Use at least 30 warm scores per path")
    if args.output.exists():
        raise FileExistsError("Benchmark outputs are immutable")
    import numpy as np
    import lightgbm
    import torch
    import prospective_fusion as fusion
    from build_reviewed_retry_cohort import verify_manifest
    from services import release_components, model_release
    from services.model_features import fusion_signals, scythe_observations
    import score_release_candidate
    imports_ms = (time.perf_counter() - STARTED) * 1000
    cohort, candidate, output = args.cohort.resolve(), args.candidate.resolve(), args.output.resolve()
    beginning = datetime.now(timezone.utc).isoformat()
    model_started = time.perf_counter()
    verify_manifest(cohort)
    verify_manifest(candidate)
    contract = json.loads((candidate / "feature_contract.json").read_text())
    manifest = json.loads((candidate / "run_manifest.json").read_text())
    if contract.get("version") != "scythe_fusion_v2" or manifest.get("status") != "experimental_only" or manifest.get("release_approved") is not False:
        raise ValueError("This benchmark accepts only explicitly experimental fusion-v2 candidates")
    hashes = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in (candidate / "checksums.sha256").read_text().splitlines()}
    models = {path: lightgbm.Booster(model_file=str(candidate / descriptor["artifact_file"]))
              for path, descriptor in contract["fusion_by_path"].items()}
    for model in models.values():
        if model.feature_name() != [field["name"] for field in contract["features"]] or model.num_model_per_iteration() != 1 or model.dump_model().get("objective", "").split()[0] != "binary":
            raise ValueError("Candidate feature order/label orientation mismatch")
    for requirements in contract["components_by_path"].values():
        for descriptor in requirements.values():
            release_components.verify_descriptor(candidate, hashes, descriptor)
    cold_model_load_ms = (time.perf_counter() - model_started) * 1000
    visual = json.loads((candidate / contract["components_by_path"]["deep_url"]["visual"]["contract_file"]).read_text())
    encoder_started = time.perf_counter()
    release_components._load_encoder(visual, WORKSPACE / "mobileclip-dataset")
    cold_encoder_load_ms = (time.perf_counter() - encoder_started) * 1000
    rows = [json.loads(line) for line in (cohort / "manifest_paired.jsonl").read_text().splitlines()]
    rows = [row for row in rows if row["split"] == "validation"]
    if not rows:
        raise ValueError("No development validation inputs")
    output.mkdir(parents=True)
    shutil.copyfile(__file__, output / "benchmark_source.py")
    normalized, originals = [], {}
    for row in rows:
        capture = row["capture_id"]
        original = json.loads(fusion.checked_file(cohort / "evidence", row["scan_evidence"]).read_text())
        observations = {}
        for name, observation in row["scythe"].items():
            if observation.get("status") != "observed":
                observations[name] = observation
                continue
            raw = json.loads(fusion.checked_file(cohort / "evidence", observation).read_text())
            observations[name] = {**observation, "provider": raw["provider"], "algorithm": raw["algorithm_version"], "unit": raw["unit"]}
        copied = {**original, "canonical_url": row["url"], "decision_at_utc": row["decision_at"], "scythe_observations": observations}
        directory = output / "inputs" / capture
        directory.mkdir(parents=True)
        image = directory / "capture.png"
        scan = directory / "scan_evidence.json"
        shutil.copyfile(fusion.checked_file(cohort / "evidence", row["screenshot"]), image)
        scan.write_text(json.dumps(copied, indent=2), encoding="utf-8")
        normalized.append({"capture_id": capture, "canonical_url": row["url"], "captured_at_utc": row["captured_at"],
            "image": {"path": image.relative_to(output).as_posix(), "sha256": fusion.sha(image)},
            "scan_evidence": {"path": scan.relative_to(output).as_posix(), "sha256": fusion.sha(scan)}})
        originals[capture] = row
    runtime = {"checked": {"registration": {"registered_at_utc": beginning}},
        "contract": contract, "models_by_path": models, "model": None, "root": candidate,
        "hashes": hashes, "components": release_components, "release": model_release,
        "signals": fusion_signals, "observations": scythe_observations, "encoder_root": WORKSPACE / "mobileclip-dataset"}
    parity = []
    current = {}

    def checked_vector(evidence, feature_contract, path):
        observed = model_release.build_vector(evidence, feature_contract, path)
        up = evidence["components"]["url_probability"]
        vp = evidence["components"]["visual_probability"]
        expected = fusion.matrix_v2([current["row"]], [up], [vp], cohort / "evidence", path)[0]
        if not np.allclose(expected, observed, equal_nan=True, atol=1e-12):
            raise ValueError("Actual runtime observation/signal/feature extraction differs from training")
        parity.append({"capture_id": current["row"]["capture_id"], "path": path, "columns": len(observed)})
        return observed

    runtime["release"] = SimpleNamespace(build_vector=checked_vector)
    for row in normalized:
        current["row"] = originals[row["capture_id"]]
        for path in ("quick_url", "deep_url"):
            score_release_candidate.score_one(runtime, row, path, output)
    runtime["release"] = model_release
    cold_first = {}
    for path in ("quick_url", "deep_url"):
        started = time.perf_counter()
        score_release_candidate.score_one(runtime, normalized[0], path, output)
        cold_first[path] = (time.perf_counter() - started) * 1000
    scores, summaries = [], {}
    rng = np.random.default_rng(42)
    for path in ("quick_url", "deep_url"):
        durations, failures = [], 0
        for index in range(args.warm_scores_per_path):
            row = normalized[index % len(normalized)]
            started = time.perf_counter()
            try:
                result = score_release_candidate.score_one(runtime, row, path, output)
                if result.get("status") != "available" or not math.isfinite(result.get("probability", float("nan"))):
                    raise ValueError("Unavailable diagnostic input")
            except Exception as exc:
                failures += 1
                result = {"status": "unavailable", "reason": type(exc).__name__}
            elapsed = (time.perf_counter() - started) * 1000
            durations.append(elapsed)
            scores.append({"capture_id": row["capture_id"], "path": path, "repetition": index, "elapsed_ms": elapsed, **result})
        values = np.asarray(durations)
        bootstrap = np.percentile(values[rng.integers(0, len(values), size=(1000, len(values)))], 95, axis=1)
        summaries[path] = {"scores": len(values), "distinct_inputs": len(normalized), "failures": failures,
            "p50_ms": float(np.percentile(values, 50)), "p95_ms": float(np.percentile(values, 95)),
            "minimum_ms": float(values.min()), "maximum_ms": float(values.max()),
            "descriptive_p95_bootstrap95_ms": np.percentile(bootstrap, [2.5, 97.5]).tolist(),
            "diagnostic_latency_budget_ms": 2000 if path == "quick_url" else 15000}
    report = {"status": "completed_development_latency_only", "release_approved": False,
        "created_at_utc": beginning, "candidate_checksums_sha256": fusion.sha(candidate / "checksums.sha256"),
        "cohort_checksums_sha256": fusion.sha(cohort / "checksums.sha256"),
        "source_sha256": fusion.sha(__file__), "source_scorer_sha256": fusion.sha(score_release_candidate.__file__),
        "imports_ms": imports_ms, "cold_artifact_validation_native_model_load_ms": cold_model_load_ms,
        "cold_encoder_load_ms": cold_encoder_load_ms,
        "first_scoring_after_parity_warmup_ms": cold_first, "warm": summaries,
        "parity": {"status": "passed", "feature_checks": parity},
        "hardware": {"platform": platform.platform(), "processor": platform.processor(), "machine": platform.machine(),
                     "logical_cpu_count": os.cpu_count(), "torch_threads": torch.get_num_threads(), "lightgbm_predict_threads": 1},
        "workload_note": args.workload_note,
        "scope": "Host-side exact candidate score_one: input checksum/URL validation, component artifact validation, image preprocessing, component inference, observation/signal extraction, fusion inference",
        "limitations": [f"Previously selected {len(normalized)} development validation inputs, repeated round-robin; not an independent holdout",
            "This is host CPU timing, not current Docker-worker qualification", "No queueing, capture, provider, or complete-scan latency",
            "Cold timings are a single process observation; OS filesystem cache may already be warm",
            "Bootstrap intervals describe repeated measurements and do not remove dependence or certify operational latency",
            "The scorer's historical time-bound context uses this actual benchmark timestamp; no holdout registration or reviewer attestation was created"],
        "records": scores}
    (output / "benchmark.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (output / "checksums.sha256").write_text("".join(f"{fusion.sha(path)}  {path.relative_to(output).as_posix()}\n" for path in sorted(output.rglob("*")) if path.is_file() and path.name != "checksums.sha256"), encoding="utf-8")
    verify_manifest(output)
    print(json.dumps({"output": str(output), "warm": summaries}))


if __name__ == "__main__":
    main()
