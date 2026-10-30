"""Score a pre-registered candidate into research predictions, never live verdicts.

Registration preflight finishes before any model is loaded. Every input is scored
once per supported path in an isolated persistent process with a 60-second limit.
A separate, checksummed training warmup can establish warm latency; without it,
predictions explicitly cannot satisfy the release warm-latency evidence gate.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib
import importlib.util
import json
import math
import multiprocessing
import os
from pathlib import Path
import platform
import sys
import time


def local_module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


evaluation = local_module("model_release_evaluation")
packaging = local_module("build_model_release")
BACKEND = Path(__file__).resolve().parents[1] / "containers/backend"
SHARED_SOURCES = ("services/model_release.py", "services/release_components.py",
                  "services/model_features/url_features.py", "services/model_features/fusion_signals.py",
                  "services/model_features/scythe_observations.py")


def verify_runtime_pins(registration):
    expected = registration.get("runtime_source_sha256", {})
    if set(expected) != set(SHARED_SOURCES):
        raise ValueError("registration must pin every shared runtime source")
    for name in SHARED_SOURCES:
        if evaluation.sha256(BACKEND / name) != expected[name]:
            raise ValueError("registered runtime source changed")


def candidate_preflight(registration_path, candidate_dir, candidate_anchor):
    checked = evaluation.validate_registration(registration_path)
    if not checked["verified"]:
        raise ValueError("registration preflight failed: " + "; ".join(checked["blockers"]))
    files = packaging.verify_candidate(candidate_dir, candidate_anchor)
    contract = evaluation.read_json(files["feature_contract.json"][0])
    if contract.get("version") == "scythe_fusion_v2":
        registered_models = evaluation.read_json(checked["files"]["models_by_path"])
        fusion_by_path = contract.get("fusion_by_path", {})
        paths = checked["registration"]["supported_paths"]
        if set(registered_models) != set(paths) or set(fusion_by_path) != set(paths):
            raise ValueError("registered path-specific models differ from contract")
        for path in paths:
            descriptor = fusion_by_path[path]
            binding = registered_models[path]
            name = descriptor.get("artifact_file")
            if (binding.get("path") != name or binding.get("sha256") != descriptor.get("artifact_sha256")
                    or files.get(name, (None, None))[1] != binding.get("sha256")):
                raise ValueError("candidate differs from registered model: " + path)
    else:
        if files.get("classifier.txt", (None, None))[1] != checked["registration"]["bindings"]["model"]["sha256"]:
            raise ValueError("candidate differs from registered model")
    if files["feature_contract.json"][1] != checked["registration"]["bindings"]["feature_contract"]["sha256"]:
        raise ValueError("candidate differs from registered feature_contract")
    if evaluation.sha256(__file__) != checked["registration"]["bindings"]["source_code"]["sha256"]:
        raise ValueError("registration must freeze this scorer implementation")
    verify_runtime_pins(checked["registration"])
    if (contract.get("positive_label") != 1 or contract.get("scoring_backend") != "lightgbm_native_booster"
            or contract.get("version") != checked["registration"]["feature_contract_version"]):
        raise ValueError("unsupported native candidate contract")
    requirements = contract.get("components_by_path", {})
    for path in checked["registration"]["supported_paths"]:
        if not isinstance(requirements.get(path), dict) or not requirements[path] or not set(requirements[path]) <= {"url", "visual"}:
            raise ValueError("missing component descriptors for " + path)
    return checked, files, contract


def load_training_warmup(binding_path, cohort, base):
    """Manifest binds a training record; no holdout input can warm the models."""
    if binding_path is None:
        return None
    manifest = evaluation.read_json(binding_path)
    if manifest.get("role") != "training_warmup":
        raise ValueError("warmup must be declared training-only")
    record_path = evaluation.bound_file(Path(binding_path).resolve().parent, manifest.get("record"))
    row = evaluation.read_json(record_path)
    if (row.get("sample_id") in {item["sample_id"] for item in cohort}
            or row.get("canonical_url") in {item["canonical_url"] for item in cohort}
            or row.get("registrable_domain") in {item["registrable_domain"] for item in cohort}):
        raise ValueError("warmup overlaps frozen holdout")
    for group in ("campaign_group", "visual_group"):
        if row.get(group) and row[group] in {item.get(group) for item in cohort}:
            raise ValueError("warmup overlaps holdout group")
    if evaluation.domain_from_canonical(row.get("canonical_url")) != row.get("registrable_domain"):
        raise ValueError("invalid training warmup URL/domain")
    # Resolve file bindings now; neither model nor holdout inference has run.
    for field in ("image", "scan_evidence"):
        if row.get(field):
            file = evaluation.bound_file(record_path.parent, row[field])
            row[field] = {"path": str(file), "sha256": row[field]["sha256"]}
    return {"row": row, "base": str(base), "manifest_sha256": evaluation.sha256(binding_path)}


def _prepare(config):
    if config.get("dataset_deps"):
        sys.path.insert(0, config["dataset_deps"])
    sys.path.insert(0, str(BACKEND))
    checked, files, contract = candidate_preflight(config["registration"], config["candidate_dir"], config["candidate_anchor"])
    components = importlib.import_module("services.release_components")
    release = importlib.import_module("services.model_release")
    signals = importlib.import_module("services.model_features.fusion_signals")
    observations = importlib.import_module("services.model_features.scythe_observations")
    import lightgbm
    if contract.get("version") == "scythe_fusion_v2":
        models = {}
        for path in checked["registration"]["supported_paths"]:
            descriptor = contract["fusion_by_path"][path]
            model = lightgbm.Booster(model_file=str(files[descriptor["artifact_file"]][0]))
            if (model.feature_name() != [field["name"] for field in contract["features"]]
                    or model.num_model_per_iteration() != 1
                    or model.dump_model().get("objective", "").split()[0] != "binary"):
                raise ValueError("candidate feature order or positive-class orientation mismatch")
            models[path] = model
        model = None
    else:
        model = lightgbm.Booster(model_file=str(files["classifier.txt"][0]))
        models = {}
        if (model.feature_name() != [field["name"] for field in contract["features"]]
                or model.num_model_per_iteration() != 1
                or model.dump_model().get("objective", "").split()[0] != "binary"):
            raise ValueError("candidate feature order or positive-class orientation mismatch")
    root = Path(config["candidate_dir"]).resolve()
    hashes = {name: digest for name, (_, digest) in files.items()}
    for path in checked["registration"]["supported_paths"]:
        for descriptor in contract["components_by_path"][path].values():
            components.verify_descriptor(root, hashes, descriptor)
    return {"checked": checked, "contract": contract, "model": model, "models_by_path": models, "root": root,
            "hashes": hashes, "components": components, "release": release,
            "signals": signals, "observations": observations, "encoder_root": Path(config["encoder_root"])}


def score_one(runtime, row, path, base):
    contract = runtime["contract"]
    image_path = evaluation.bound_file(Path(base), row["image"]) if path == "deep_url" and row.get("image") else None
    features = {}
    # Preserve the legacy evaluator's ability to score an attached scan bundle.
    # v2 quick_url has a narrower contract and must ignore deep-only evidence.
    has_legacy_scan_evidence = contract.get("version") != "scythe_fusion_v2"
    if (path == "deep_url" or has_legacy_scan_evidence) and row.get("scan_evidence"):
        features = evaluation.read_json(evaluation.bound_file(Path(base), row["scan_evidence"]))
        if (not row.get("capture_id") or features.get("capture_id") != row["capture_id"]
                or (features.get("canonical_url") is not None and features["canonical_url"] != row["canonical_url"])):
            raise ValueError("scan evidence is not tied to capture")
    reference_time = features.get("decision_at_utc", row.get("captured_at_utc"))
    if (evaluation.utc(reference_time) < evaluation.utc(row["captured_at_utc"])
            or evaluation.utc(reference_time) > evaluation.utc(runtime["checked"]["registration"]["registered_at_utc"])):
        raise ValueError("historical decision time outside captured/registered bounds")
    components = runtime["components"].score_components(runtime["root"], runtime["hashes"], contract["components_by_path"][path], row["canonical_url"], image_path, runtime["encoder_root"])
    for name, descriptor in contract["components_by_path"][path].items():
        if components[name].get("status") != "observed" or components[name].get("artifact_hashes") != descriptor:
            raise ValueError("component unavailable")
    evidence = {"component_results": components,
                "components": {**{f"{key}_probability": value.get("phishing_probability") for key, value in components.items()},
                               "visual_available": int(components.get("visual", {}).get("status") == "observed")},
                "scythe": runtime["observations"].extract_scythe_observations(features.get("scythe_observations", {}), contract, features.get("capture_id"), reference_time),
                "scan_signals": runtime["signals"].extract_scan_signals(features.get("browser_features"), features.get("sandbox_features"), features.get("consistency_report"))}
    if contract.get("version") == "scythe_fusion_v2" and path == "quick_url":
        evidence["scythe"] = {key: (0 if key.endswith("_available") else None)
                              for key in evidence["scythe"]}
        evidence["scan_signals"] = {key: (0 if key.endswith("_available") else None)
                                    for key in evidence["scan_signals"]}
        evidence["components"]["visual_probability"] = None
        evidence["components"]["visual_available"] = 0
    vector = runtime["release"].build_vector(evidence, contract,
        path if contract.get("version") == "scythe_fusion_v2" else None)
    model = runtime["models_by_path"][path] if contract.get("version") == "scythe_fusion_v2" else runtime["model"]
    probability = float(model.predict([vector], num_threads=1)[0])
    if not math.isfinite(probability) or not 0 <= probability <= 1:
        raise ValueError("invalid candidate probability")
    return {"status": "available", "probability": probability}


def worker(connection, config):
    try:
        runtime = _prepare(config)
        connection.send({"ready": True})
    except Exception:
        connection.send({"ready": False, "reason": "candidate_initialization_failed"})
        return
    while True:
        try:
            request = connection.recv()
        except EOFError:
            return
        if request is None:
            return
        try:
            result = score_one(runtime, request["row"], request["path"], request["base"])
        except Exception:
            result = {"status": "unavailable", "probability": None, "error_reason": "candidate_input_unavailable"}
        connection.send(result)


class IsolatedScorer:
    def __init__(self, config, *, target=worker, timeout_seconds=60):
        self.context = multiprocessing.get_context("spawn")
        self.config, self.target, self.timeout = config, target, min(timeout_seconds, 60)
        self.process = self.connection = None

    def start(self):
        parent, child = self.context.Pipe()
        self.connection = parent
        self.process = self.context.Process(target=self.target, args=(child, self.config), daemon=True)
        self.process.start()
        child.close()
        if not parent.poll(self.timeout):
            self.close()
            raise TimeoutError("candidate worker initialization timed out")
        try:
            ready = parent.recv()
        except EOFError as exc:
            self.close()
            raise ValueError("candidate worker initialization failed") from exc
        if not ready.get("ready"):
            self.close()
            raise ValueError("candidate worker initialization failed")

    def score(self, row, path, base):
        if self.process is None:
            self.start()
        started = time.monotonic()
        try:
            self.connection.send({"row": row, "path": path, "base": str(base)})
            if not self.connection.poll(self.timeout):
                self.close()
                result = {"status": "unavailable", "probability": None, "error_reason": "timeout"}
            else:
                result = self.connection.recv()
        except (EOFError, BrokenPipeError, OSError):
            self.close()
            result = {"status": "unavailable", "probability": None, "error_reason": "worker_failure"}
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        return result

    def close(self):
        if self.process is not None:
            if self.process.is_alive():
                self.process.terminate()
            self.process.join(timeout=3)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(timeout=3)
            self.process = None
        if self.connection is not None:
            self.connection.close()
            self.connection = None


def score_candidate(registration_path, candidate_dir, candidate_anchor, encoder_root, output_dir, *, dataset_deps=None, warmup_manifest=None, scorer_factory=IsolatedScorer):
    # This must precede creating the worker, importing ML modules or reading warmup.
    checked, _, _ = candidate_preflight(registration_path, candidate_dir, candidate_anchor)
    output_dir = Path(output_dir).resolve()
    if output_dir.exists():
        raise FileExistsError("prediction output version already exists")
    registration = checked["registration"]
    warmup = load_training_warmup(warmup_manifest, checked["cohort"], checked["files"]["cohort"].parent)
    config = {"registration": str(Path(registration_path).resolve()), "candidate_dir": str(Path(candidate_dir).resolve()),
              "candidate_anchor": candidate_anchor, "encoder_root": str(Path(encoder_root).resolve()),
              "dataset_deps": str(Path(dataset_deps).resolve()) if dataset_deps else None}
    output_dir.mkdir(parents=True, exist_ok=False)
    metadata = {"started_at_utc": datetime.now(timezone.utc).isoformat(),
                "registration_sha256": evaluation.sha256(registration_path),
                "target_hardware": {"machine": platform.machine(), "processor": platform.processor(), "cpu_count": os.cpu_count(), "platform": platform.platform()},
                "runtime_source_sha256": registration["runtime_source_sha256"],
                "per_input_process_timeout_seconds": 60, "probabilities_are_experimental": True,
                "warmup_manifest_sha256": warmup["manifest_sha256"] if warmup else None}
    names = {"feature_contract": "feature_contract_sha256", "thresholds": "thresholds_sha256",
             "cohort": "holdout_sha256", "source_code": "source_code_sha256"}
    if registration.get("feature_contract_version") == "scythe_fusion_v2":
        metadata["model_sha256_by_path"] = checked["model_sha256_by_path"]
    elif "model" in checked["files"]:
        names["model"] = "model_sha256"
    metadata.update({key: evaluation.sha256(checked["files"][name]) for name, key in names.items()})
    scorer = scorer_factory(config)
    rows, warmed = [], set()
    metadata["training_warmup_results"] = []
    try:
        initialized = time.monotonic()
        scorer.start()
        metadata["worker_initialization_elapsed_ms"] = round((time.monotonic() - initialized) * 1000, 3)
        for path in registration["supported_paths"]:
            if warmup:
                result = scorer.score(warmup["row"], path, warmup["base"])
                metadata["training_warmup_results"].append({"path": path, **result})
                if result["status"] == "available":
                    warmed.add(path)
            for row in checked["cohort"]:
                # A killed worker loses its warm caches. Re-warm only with the
                # separate training input, never by repeating a holdout sample.
                if scorer.process is None:
                    warmed.clear()
                    scorer.start()
                    if warmup:
                        result = scorer.score(warmup["row"], path, warmup["base"])
                        if result["status"] == "available":
                            warmed.add(path)
                is_warm = path in warmed
                result = scorer.score(row, path, checked["files"]["cohort"].parent)
                rows.append({"sample_id": row["sample_id"], "path": path, "latency_state": "warm" if is_warm else "cold_or_unverified", **result})
                # An append-only journal preserves failures if interrupted.
                with (output_dir / "predictions.jsonl").open("a", encoding="utf-8") as journal:
                    journal.write(json.dumps(rows[-1], allow_nan=False) + "\n")
    finally:
        scorer.close()
    metadata["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    metadata["warm_latency_includes_preprocessing_validation_inference"] = bool(rows) and all(row["latency_state"] == "warm" for row in rows)
    metadata["cold_or_unverified_record_count"] = sum(row["latency_state"] != "warm" for row in rows)
    target = output_dir / "predictions.json"
    target.write_text(json.dumps({"metadata": metadata, "records": rows}, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (output_dir / "checksums.sha256").write_text("".join(f"{evaluation.sha256(output_dir / name)}  {name}\n" for name in ("predictions.json", "predictions.jsonl")), encoding="ascii")
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--candidate-checksums-sha256", required=True)
    parser.add_argument("--encoder-source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--dataset-deps", type=Path)
    parser.add_argument("--training-warmup", type=Path)
    args = parser.parse_args()
    if args.dataset_deps:
        sys.path.insert(0, str(args.dataset_deps.resolve()))
    try:
        target = score_candidate(args.registration, args.candidate_dir, args.candidate_checksums_sha256,
                                 args.encoder_source_dir, args.output_dir, dataset_deps=args.dataset_deps,
                                 warmup_manifest=args.training_warmup)
    except (OSError, ValueError, TypeError, KeyError, TimeoutError) as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc), "activated": False}))
        return 2
    print(json.dumps({"status": "research_predictions_saved", "predictions": str(target), "activated": False}))
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
