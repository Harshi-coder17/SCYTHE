"""Opt-in experimental URL and MobileCLIP scoring, isolated from risk fusion."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import logging
import math
import os
from pathlib import Path
import re
import time

import redis
from celery.exceptions import SoftTimeLimitExceeded

from celery_worker import celery
from config import settings
from database.database import get_db_session
from database.models import Scan
from services.model_features.url_features import FEATURE_NAMES, build_url_feature_vector
from tasks import validate_scan_id

logger = logging.getLogger(__name__)
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_REDIS = redis.from_url(settings.REDIS_URL)
_REPORT_NAME = "shadow_model_report.json"
_ERROR_REASONS = {
    "disabled", "missing_url", "invalid_http_url", "missing_screenshot",
    "bundle_unavailable", "checksum_mismatch", "contract_mismatch",
    "inference_failed", "timeout", "duplicate_task", "worker_failure",
}


def _scan_dir(scan_id: str) -> Path:
    validate_scan_id(scan_id)
    root = Path(settings.SHARED_DIR).resolve()
    path = (root / scan_id).resolve()
    if path.parent != root:
        raise ValueError("worker_failure")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, value: dict) -> None:
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temp, path)


def _unavailable(model_version: str, reason: str) -> dict:
    return {
        "model_version": model_version,
        "contract_version": None,
        "status": "unavailable",
        "phishing_probability": None,
        "artifact_hashes": {},
        "error_reason": reason if reason in _ERROR_REASONS else "worker_failure",
    }


def _verify_bundle(bundle_dir: str, expected_manifest_sha256: str,
                   required_files: set[str]) -> tuple[Path, dict[str, str]]:
    """Verify a local bundle against a separately configured trust anchor."""
    root = Path(bundle_dir).resolve()
    manifest = root / "checksums.sha256"
    if not bundle_dir or not expected_manifest_sha256 or not _HASH_RE.fullmatch(expected_manifest_sha256.lower()):
        raise ValueError("bundle_unavailable")
    if not root.is_dir() or not manifest.is_file():
        raise ValueError("bundle_unavailable")
    actual_manifest_sha256 = _sha256(manifest)
    if actual_manifest_sha256 != expected_manifest_sha256.lower():
        raise ValueError("checksum_mismatch")

    entries: dict[str, str] = {}
    for line in manifest.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})  ([A-Za-z0-9_./-]+)", line)
        if not match:
            raise ValueError("contract_mismatch")
        digest, name = match.groups()
        parts = name.split("/")
        if (name in entries or name.startswith("/") or "\\" in name
                or any(part in {"", ".", ".."} for part in parts)):
            raise ValueError("contract_mismatch")
        target = (root / Path(*parts)).resolve()
        if not target.is_relative_to(root) or not target.is_file() or _sha256(target) != digest.lower():
            raise ValueError("checksum_mismatch")
        entries[name] = digest.lower()
    if not required_files.issubset(entries):
        raise ValueError("contract_mismatch")
    return root, entries


def _score_url(raw_url: str) -> dict:
    model_version = "lightgbm_dev_v2"
    try:
        result = build_url_feature_vector(raw_url)
        if result["status"] != "observed":
            raise ValueError(result.get("reason") or "invalid_http_url")
        bundle, hashes = _verify_bundle(
            settings.SHADOW_LIGHTGBM_BUNDLE_DIR,
            settings.SHADOW_LIGHTGBM_CHECKSUMS_SHA256,
            {"classifier.txt", "feature_contract.json", "threshold.json", "run_manifest.json"},
        )
        contract = json.loads((bundle / "feature_contract.json").read_text(encoding="utf-8"))
        manifest = json.loads((bundle / "run_manifest.json").read_text(encoding="utf-8"))
        if (contract.get("model_version") != model_version
                or manifest.get("model_version") != model_version
                or contract.get("positive_label") != 1
                or contract.get("status") != "experimental_only"
                or contract.get("scoring_backend") != "lightgbm_native_booster"
                or tuple(contract.get("features", ())) != FEATURE_NAMES):
            raise ValueError("contract_mismatch")
        # The shadow bundle uses LightGBM's native text model, avoiding a
        # scikit-learn pickle-version dependency for this URL-only scorer.
        import lightgbm
        import numpy as np

        classifier = lightgbm.Booster(model_file=str(bundle / "classifier.txt"))
        vector = np.asarray([result["values"]], dtype=np.float64)
        probabilities = np.asarray(classifier.predict(vector), dtype=np.float64)
        if probabilities.shape != (1,):
            raise ValueError("contract_mismatch")
        probability = float(probabilities[0])
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise ValueError("inference_failed")
        return {
            "model_version": model_version,
            "contract_version": contract["model_version"],
            "status": "observed",
            "phishing_probability": probability,
            "artifact_hashes": {"checksums_sha256": _sha256(bundle / "checksums.sha256"),
                                "classifier_sha256": hashes["classifier.txt"],
                                "classifier_format": "lightgbm_native_text"},
            "error_reason": None,
        }
    except ValueError as exc:
        reason = str(exc)
        return _unavailable(model_version, reason)
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        logger.exception("Shadow URL scoring failed")
        return _unavailable(model_version, "inference_failed")


def _score_visual(image_path: Path) -> dict:
    model_version = "mobileclip_v2"
    try:
        if not image_path.is_file():
            raise ValueError("missing_screenshot")
        bundle, hashes = _verify_bundle(
            settings.SHADOW_MOBILECLIP_ARTIFACT_DIR,
            settings.SHADOW_MOBILECLIP_CHECKSUMS_SHA256,
            {"classifier.joblib", "feature_contract.json", "encoder_ref.json", "threshold.json", "run_manifest.json"},
        )
        scorer_path = Path(settings.SHADOW_MOBILECLIP_SCORER_PATH).resolve()
        source_root = Path(settings.SHADOW_MOBILECLIP_SOURCE_DIR).resolve()
        expected_scorer_hash = settings.SHADOW_MOBILECLIP_SCORER_SHA256.lower()
        if (not settings.SHADOW_MOBILECLIP_SCORER_PATH or not settings.SHADOW_MOBILECLIP_SOURCE_DIR
                or not _HASH_RE.fullmatch(expected_scorer_hash)):
            raise ValueError("bundle_unavailable")
        if scorer_path.parent != source_root or not scorer_path.is_file():
            raise ValueError("bundle_unavailable")
        scorer_hash = _sha256(scorer_path)
        if scorer_hash != expected_scorer_hash:
            raise ValueError("checksum_mismatch")
        spec = importlib.util.spec_from_file_location("scythe_mobileclip_v2_scorer", scorer_path)
        if spec is None or spec.loader is None:
            raise ValueError("contract_mismatch")
        scorer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scorer)
        scorer.ROOT = source_root
        scorer.ARTIFACT = bundle
        contract = scorer.verify_artifact()
        if contract.get("version") != model_version:
            raise ValueError("contract_mismatch")
        result = scorer.score(str(image_path))
        probability = result.get("visual_phishing_probability")
        if result.get("status") != "observed" or not isinstance(probability, (int, float)):
            raise ValueError("inference_failed")
        probability = float(probability)
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise ValueError("inference_failed")
        encoder_ref = json.loads((bundle / "encoder_ref.json").read_text(encoding="utf-8"))
        return {
            "model_version": model_version,
            "contract_version": contract["version"],
            "status": "observed",
            "phishing_probability": probability,
            "artifact_hashes": {"checksums_sha256": _sha256(bundle / "checksums.sha256"),
                                "classifier_sha256": hashes["classifier.joblib"],
                                "checkpoint_sha256": encoder_ref.get("checkpoint_sha256"),
                                "scorer_sha256": scorer_hash},
            "error_reason": None,
        }
    except ValueError as exc:
        reason = str(exc)
        return _unavailable(model_version, reason)
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        logger.exception("Shadow MobileCLIP scoring failed")
        return _unavailable(model_version, "inference_failed")


def _get_scan_url(scan_id: str) -> str | None:
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        return scan.url if scan else None


def _write_report(scan_dir: Path, scan_id: str, models: dict, started: float,
                  input_key: str | None = None) -> dict:
    elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
    observed = any(item.get("status") == "observed" for item in models.values())
    report = {
        "schema_version": 1,
        "scan_id": scan_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "observed" if observed else "unavailable",
        "experimental": True,
        "automatic_incident_signal": False,
        "input_key_sha256": input_key,
        "elapsed_ms": elapsed_ms,
        "models": models,
    }
    _atomic_json(scan_dir / _REPORT_NAME, report)
    return report


@celery.task(
    bind=True,
    name="tasks.shadow_model_scoring",
    queue="shadow",
    acks_late=True,
    max_retries=0,
    soft_time_limit=55,
    time_limit=60,
)
def shadow_model_scoring_task(self, scan_id: str) -> dict:
    """Score configured experimental models and write a private scan artifact."""
    started = time.monotonic()
    validate_scan_id(scan_id)
    scan_dir = _scan_dir(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    if not settings.SHADOW_SCORING_ENABLED:
        return _write_report(scan_dir, scan_id, {
            "url": _unavailable("lightgbm_dev_v2", "disabled"),
            "visual": _unavailable("mobileclip_v2", "disabled"),
        }, started)

    try:
        raw_url = _get_scan_url(scan_id)
        image_path = scan_dir / "browser.png"
        normalized = build_url_feature_vector(raw_url or "")
        url_hash = hashlib.sha256((normalized.get("canonical_url") or raw_url or "").encode("utf-8")).hexdigest()
        image_hash = _sha256(image_path) if image_path.is_file() else "missing"
        input_key = hashlib.sha256(
            f"{scan_id}|lightgbm_dev_v2|mobileclip_v2|{url_hash}|{image_hash}".encode("ascii")
        ).hexdigest()
        lock_key = f"scythe:shadow-score:{input_key}"
        try:
            acquired = _REDIS.set(lock_key, "running", nx=True, ex=3600)
        except Exception:
            logger.exception("Shadow scoring deduplication unavailable for %s", scan_id)
            return _write_report(scan_dir, scan_id, {
                "url": _unavailable("lightgbm_dev_v2", "worker_failure"),
                "visual": _unavailable("mobileclip_v2", "worker_failure"),
            }, started, input_key)
        if not acquired:
            existing_path = scan_dir / _REPORT_NAME
            if existing_path.is_file():
                try:
                    existing = json.loads(existing_path.read_text(encoding="utf-8"))
                    if existing.get("input_key_sha256") == input_key:
                        return existing
                except (OSError, json.JSONDecodeError):
                    pass
            return _write_report(scan_dir, scan_id, {
                "url": _unavailable("lightgbm_dev_v2", "duplicate_task"),
                "visual": _unavailable("mobileclip_v2", "duplicate_task"),
            }, started, input_key)

        models = {}
        models["url"] = (_score_url(raw_url) if raw_url else
                         _unavailable("lightgbm_dev_v2", "missing_url"))
        models["visual"] = _score_visual(image_path) if image_path.is_file() else \
            _unavailable("mobileclip_v2", "missing_screenshot")
        return _write_report(scan_dir, scan_id, models, started, input_key)
    except SoftTimeLimitExceeded:
        models = {
            "url": _unavailable("lightgbm_dev_v2", "timeout"),
            "visual": _unavailable("mobileclip_v2", "timeout"),
        }
        try:
            return _write_report(scan_dir, scan_id, models, started)
        except Exception:
            logger.exception("Could not persist timed-out shadow report for %s", scan_id)
            return {"scan_id": scan_id, "status": "unavailable", "error_reason": "timeout"}
    except Exception:
        logger.exception("Shadow scoring failed for %s", scan_id)
        models = {
            "url": _unavailable("lightgbm_dev_v2", "worker_failure"),
            "visual": _unavailable("mobileclip_v2", "worker_failure"),
        }
        try:
            return _write_report(scan_dir, scan_id, models, started)
        except Exception:
            logger.exception("Could not persist failed shadow report for %s", scan_id)
            return {"scan_id": scan_id, "status": "unavailable", "error_reason": "worker_failure"}
