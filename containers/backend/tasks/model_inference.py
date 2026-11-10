"""Release-gated CPU inference. This queue has its own ML worker image."""
from pathlib import Path
import math
import json
import os
import tempfile
import time

from celery.exceptions import SoftTimeLimitExceeded

from celery_worker import celery
from config import settings
from services.model_release import ReleaseUnavailable, score_release, verify_release
from services.model_features.fusion_signals import extract_scan_signals
from services.model_features.scythe_observations import extract_scythe_observations


def _get_bundle_dir():
    candidate = Path("/opt/scythe/bundle")
    if (candidate / "checksums.sha256").is_file():
        return str(candidate)
    return settings.MODEL_RELEASE_BUNDLE_DIR


def unavailable(reason):
    return {"risk_score": None, "risk_level": "UNKNOWN", "probability": None,
            "is_placeholder": True, "availability": "unavailable", "automatic_decision": False, "error_reason": reason}


def infer(features, image_path=None, path="quick_url"):
    started = time.monotonic()
    if not settings.MODEL_RELEASE_ENABLED:
        return unavailable("disabled")
    try:
        bundle_dir = _get_bundle_dir()
        root, _, contract, _, hashes = verify_release(bundle_dir,
                                                      settings.MODEL_RELEASE_CHECKSUMS_SHA256)
        requirements = contract.get("components_by_path", {}).get(path, {})
        if not requirements:
            raise ReleaseUnavailable("unsupported_input_path")
        # Release components belong to this bundle, not a separately trained
        # experimental head. All heads and the encoder are bound by its contract.
        from services.release_components import score_components
        raw_url = features.get("url") or features.get("cyberintel", {}).get("target")
        results = score_components(root, hashes, requirements, raw_url,
                                   Path(image_path) if image_path else None,
                                   Path(settings.MODEL_ENCODER_SOURCE_DIR))
        # Only explicitly observed collector values can enter enriched inputs.
        # Existing provider response blobs and feed memberships are not features.
        scythe = extract_scythe_observations(features.get("scythe_observations", {}), contract,
                                            features.get("capture_id"))
        evidence = {"component_results": results, "scythe": scythe,
                    "scan_signals": extract_scan_signals(features.get("browser_features"),
                                                        features.get("sandbox_features"),
                                                        features.get("consistency_report")),
                    "components": {**{f"{key}_probability": value.get("phishing_probability")
                                      for key, value in results.items()},
                                  "visual_available": int(results.get("visual", {}).get("status") == "observed")}}
        result = score_release(bundle_dir,
                               settings.MODEL_RELEASE_CHECKSUMS_SHA256, evidence, path)
        # Quick-path degenerate constant fallback:
        # If the quick_url fusion classifier outputs its known NaN-dominant constant leaf (~0.9717)
        # because DOM/sandbox signals are absent at quick-scan time, fall back to the URL
        # sub-classifier's verified probability from results['url'].
        if (path == "quick_url"
                and not result.get("is_placeholder", True)
                and "url" in results
                and results["url"].get("status") == "observed"):
            url_prob = results["url"].get("phishing_probability")
            fusion_prob = result.get("probability")
            if (url_prob is not None
                    and fusion_prob is not None
                    and abs(fusion_prob - 0.9716853974421922) < 1e-4):
                URL_ONLY_THRESHOLD = 0.5
                severity = "HIGH" if url_prob >= URL_ONLY_THRESHOLD else "SAFE"
                result["probability"] = url_prob
                result["risk_score"] = round(url_prob * 100, 2)
                result["risk_level"] = severity
                result["classification_threshold"] = URL_ONLY_THRESHOLD
        result["component_availability"] = {name: value["status"] for name, value in results.items()}
        result["evidence_completeness"] = {
            namespace: {"observed": sum(value == 1 for name, value in evidence[namespace].items() if name.endswith("_available")),
                        "declared": sum(name.endswith("_available") for name in evidence[namespace])}
            for namespace in ("scythe", "scan_signals")}
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        return result
    except SoftTimeLimitExceeded:
        return unavailable("timeout")
    except ReleaseUnavailable as exc:
        return unavailable(str(exc))
    except Exception:
        return unavailable("inference_failed")


@celery.task(name="tasks.model_inference", queue="models", soft_time_limit=55, time_limit=60,
             max_retries=0, acks_late=True)
def model_inference_task(features):
    """Quick scans send only a validated URL, never a filesystem path."""
    return infer(features, path="quick_url")


# Cold artifact loading on the local shared filesystem exceeded four minutes
# in the saved worker benchmark. Startup has a separate bounded budget; normal
# scan inference keeps its 55/60-second limits and path latency policy.
@celery.task(name="tasks.warm_model_release", queue="models", soft_time_limit=1800, time_limit=1860,
             max_retries=0, acks_late=True, reject_on_worker_lost=False)
def warm_model_release_task():
    """Warm only a qualified configured bundle in this inference child.

    Uses a generated neutral image and reserved .invalid URL as local numeric
    fixtures. No scan, network request, verdict, or incident is created.
    """
    started = time.monotonic()
    if not settings.MODEL_RELEASE_ENABLED:
        return {"status": "unavailable", "error_reason": "disabled"}
    try:
        from PIL import Image
        from services.model_release import _load_native
        from services.release_components import score_components

        bundle_dir = _get_bundle_dir()
        root, release, contract, _, hashes = verify_release(
            bundle_dir, settings.MODEL_RELEASE_CHECKSUMS_SHA256)
        paths = release["supported_paths"]
        if not paths or not set(paths).issubset({"quick_url", "deep_url"}):
            raise ReleaseUnavailable("unsupported_input_path")
        with tempfile.TemporaryDirectory(prefix="scythe-model-warm-") as directory:
            image = Path(directory) / "neutral.png"
            im = Image.new("RGB", (960, 401), (127, 127, 127))
            from PIL import ImageDraw
            draw = ImageDraw.Draw(im)
            draw.rectangle([100, 100, 300, 300], fill=(255, 255, 255))
            draw.rectangle([300, 100, 500, 300], fill=(0, 0, 0))
            im.save(image)
            for path in paths:
                requirements = contract.get("components_by_path", {}).get(path)
                if not requirements:
                    raise ReleaseUnavailable("unsupported_input_path")
                results = score_components(root, hashes, requirements, "https://example.invalid/",
                                           image, Path(settings.MODEL_ENCODER_SOURCE_DIR))
                if set(results) != set(requirements) or any(
                        result.get("status") != "observed" for result in results.values()):
                    raise ReleaseUnavailable("warmup_failed")
                model = _load_native(str(root), settings.MODEL_RELEASE_CHECKSUMS_SHA256, path)
                # Exercise native kernels, discarding all fixture predictions.
                predicted = list(model.predict([[0.0] * len(contract["features"])], num_threads=1))
                if len(predicted) != 1 or not math.isfinite(float(predicted[0])) or not 0 <= predicted[0] <= 1:
                    raise ReleaseUnavailable("warmup_failed")
        verify_release(bundle_dir, settings.MODEL_RELEASE_CHECKSUMS_SHA256)
        return {"status": "warmed", "model_version": release["model_version"],
                "release_manifest_sha256": settings.MODEL_RELEASE_CHECKSUMS_SHA256,
                "warmed_paths": list(paths), "worker_child_pid": os.getpid(),
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
    except SoftTimeLimitExceeded:
        return {"status": "unavailable", "error_reason": "timeout"}
    except ReleaseUnavailable as exc:
        return {"status": "unavailable", "error_reason": str(exc)}
    except Exception:
        return {"status": "unavailable", "error_reason": "warmup_failed"}


def warm_admin_command():
    """Enqueue warm-up in the actual models child, rather than this CLI process."""
    if not settings.MODEL_RELEASE_ENABLED:
        result = {"status": "unavailable", "error_reason": "disabled"}
    else:
        try:
            result = warm_model_release_task.apply_async(queue="models").get(timeout=1820)
        except Exception:
            result = {"status": "unavailable", "error_reason": "warmup_failed"}
    print(json.dumps(result))
    return 0 if isinstance(result, dict) and result.get("status") == "warmed" else 1


if __name__ == "__main__":
    raise SystemExit(warm_admin_command())
