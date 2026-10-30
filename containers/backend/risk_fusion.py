"""
Risk Fusion Engine
==================
Assembles all evidence (CyberIntel, browser features, sandbox features,
consistency report) and produces the final risk verdict.
"""

import logging
import math
from pathlib import Path
import re

from config import settings

logger = logging.getLogger(__name__)


# Exact 15 ordered features specified in schema.json (feature_matrix_columns)
FEATURE_COLUMNS = [
    "url_length",
    "host_length",
    "is_https",
    "is_ip_host",
    "subdomain_count",
    "hyphen_count",
    "digit_count",
    "special_count",
    "at_symbol",
    "question_mark_count",
    "path_length",
    "query_length",
    "has_punycode",
    "url_shortener_used",
    "is_bogon_space",
]

# Compatibility sentinel for old imports. Runtime models are loaded only by the
# checksum-verified model worker; experimental/local files are never activated.
model = None


def _resolve_model_path() -> Path | None:
    """Legacy hook retained for compatibility; runtime does not scan model paths."""
    return None


def _load_model_from_file(path: Path):
    """Reject direct artifact loading; verified bundles use services.model_release."""
    raise ValueError("unverified_model_loading_disabled")


def load_model():
    """Legacy hook that intentionally never loads standalone model artifacts."""
    global model
    model = "MODEL_NOT_AVAILABLE"
    return model


def build_feature_vector(features) -> list[float]:
    """Extract the exact 15 ordered features specified in schema.json.

    Extracts a complete 15-feature row. Missing, malformed, or partial input
    raises ValueError so an incomplete row can never become a confident score.
    """
    if isinstance(features, (list, tuple)):
        if len(features) != len(FEATURE_COLUMNS):
            raise ValueError("invalid_feature_count")
        return [_required_float(value) for value in features]

    if not isinstance(features, dict):
        raise ValueError("invalid_feature_input")

    extracted: dict[str, float] = {}

    # 1. Search for URL string to extract URL-based features
    url = (
        features.get("url")
        or features.get("target")
        or (features.get("browser_features") if isinstance(features.get("browser_features"), dict) else {}).get("url")
        or (features.get("browser_features") if isinstance(features.get("browser_features"), dict) else {}).get("target")
        or (features.get("browser_features") if isinstance(features.get("browser_features"), dict) else {}).get("final_url")
        or (features.get("cyberintel") if isinstance(features.get("cyberintel"), dict) else {}).get("target")
        or (features.get("cyberintel") if isinstance(features.get("cyberintel"), dict) else {}).get("url")
    )

    if isinstance(url, str) and url.strip():
        try:
            from services.model_features.url_features import build_url_feature_vector
            res = build_url_feature_vector(url.strip())
            if res.get("status") == "observed" and res.get("values"):
                for name, val in zip(FEATURE_COLUMNS, res["values"]):
                    if val is not None:
                        extracted[name] = _required_float(val)
        except Exception as exc:
            logger.debug("URL feature extraction failed for %s: %s", url, exc)

    # 2. Check for url_features nested dictionary
    url_feats = features.get("url_features")
    if isinstance(url_feats, dict):
        for name in FEATURE_COLUMNS:
            if name in url_feats:
                extracted[name] = _required_float(url_feats[name])

    # 3. Check for direct feature keys in input features dictionary
    for name in FEATURE_COLUMNS:
        if name in features:
            extracted[name] = _required_float(features[name])

    # 4. Check for is_bogon_space in cyberintel or scythe_observations if not observed
    if "is_bogon_space" not in extracted or extracted["is_bogon_space"] == 0.0:
        ci = features.get("cyberintel")
        if isinstance(ci, dict):
            if "is_bogon_space" in ci and ci["is_bogon_space"] is not None:
                extracted["is_bogon_space"] = _required_float(ci["is_bogon_space"])
            elif "scythe_observations" in ci and isinstance(ci["scythe_observations"], dict):
                obs = ci["scythe_observations"]
                if "is_bogon_space" in obs and obs["is_bogon_space"] is not None:
                    extracted["is_bogon_space"] = _required_float(obs["is_bogon_space"])

    missing = [name for name in FEATURE_COLUMNS if name not in extracted]
    if missing:
        raise ValueError("missing_features")
    return [extracted[name] for name in FEATURE_COLUMNS]


def _required_float(value) -> float:
    """Accept only explicit finite numeric features; never invent a default."""
    if isinstance(value, bool):
        raise ValueError("invalid_feature_value")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("invalid_feature_value") from exc
    if not math.isfinite(result):
        raise ValueError("invalid_feature_value")
    return result


def predict_probability(feature_vector) -> float | None:
    """Predict phishing probability for an ordered 15-feature vector.

    If model is 'MODEL_NOT_AVAILABLE' or unavailable, returns None.
    If model is a loaded Booster or scikit-learn estimator, returns float in [0.0, 1.0].
    """
    global model
    if model is None:
        load_model()

    if model == "MODEL_NOT_AVAILABLE" or model is None:
        return None

    # Normalize strictly; invalid or incomplete rows never get zero-filled.
    if hasattr(feature_vector, "tolist"):
        feature_vector = feature_vector.tolist()
    try:
        if isinstance(feature_vector, dict):
            feature_vector = build_feature_vector(feature_vector)
        elif isinstance(feature_vector, (list, tuple)):
            if len(feature_vector) == 1 and isinstance(feature_vector[0], (list, tuple)):
                feature_vector = feature_vector[0]
            feature_vector = build_feature_vector(feature_vector)
        else:
            logger.warning("Unsupported feature vector type: %s", type(feature_vector))
            return None
    except ValueError:
        logger.warning("Rejected invalid URL-model feature vector")
        return None

    try:
        # 1. Scikit-learn estimator / LGBMClassifier with predict_proba
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba([feature_vector])
            if hasattr(model, "classes_") and 1 in getattr(model, "classes_"):
                pos_idx = list(model.classes_).index(1)
                prob = float(probs[0][pos_idx])
            elif len(probs[0]) > 1:
                prob = float(probs[0][1])
            else:
                prob = float(probs[0][0])
        # 2. LightGBM Booster or model with predict()
        elif hasattr(model, "predict"):
            res = model.predict([feature_vector])
            if hasattr(res, "__len__") and len(res) > 0:
                prob = float(res[0])
            else:
                prob = float(res)
        # 3. Callable model
        elif callable(model):
            res = model([feature_vector])
            if hasattr(res, "__len__") and len(res) > 0:
                prob = float(res[0])
            else:
                prob = float(res)
        else:
            logger.error("Loaded model lacks predict or predict_proba methods")
            return None

        if not math.isfinite(prob):
            logger.warning("Prediction produced non-finite value: %s", prob)
            return None

        return float(max(0.0, min(1.0, prob)))
    except Exception as exc:
        logger.exception("Inference failed in predict_probability: %s", exc)
        return None


def get_risk_level(score):
    if score is None:
        return "UNKNOWN"
    if score < settings.SAFE_THRESHOLD:
        return "SAFE"
    elif score < settings.LOW_THRESHOLD:
        return "LOW"
    elif score < settings.MEDIUM_THRESHOLD:
        return "MEDIUM"
    elif score < settings.HIGH_THRESHOLD:
        return "HIGH"
    return "CRITICAL"


def run_risk_fusion(features):
    # Every runtime score, even in enabled mode, must pass through the isolated
    # worker's pinned checksum manifest, evaluation record, and approved policy.
    from tasks.model_inference import model_inference_task, unavailable
    if not settings.MODEL_RELEASE_ENABLED:
        return unavailable("release_not_configured")
    if not isinstance(features, dict):
        return unavailable("invalid_input")
    url = features.get("url")
    if not isinstance(url, str) or not url.strip():
        url = (features.get("cyberintel") or {}).get("target") if isinstance(features.get("cyberintel"), dict) else None
    if not isinstance(url, str) or not url.strip():
        return unavailable("invalid_input")
    try:
        job = model_inference_task.apply_async(args=[{"url": url.strip()}], queue="models", expires=10)
        result = job.get(timeout=5)
        if not isinstance(result, dict) or not isinstance(result.get("is_placeholder"), bool):
            return unavailable("inference_failed")
        if result["is_placeholder"]:
            # Do not let a malformed worker response attach a confident severity
            # or probability to an unavailable result.
            reason = result.get("error_reason")
            if (result.get("availability") != "unavailable"
                    or result.get("risk_level") != "UNKNOWN"
                    or result.get("risk_score") is not None
                    or result.get("probability") is not None
                    or result.get("automatic_decision") is not False
                    or not isinstance(reason, str) or not reason.isascii()
                    or not reason.replace("_", "").isalnum() or len(reason) > 64):
                return unavailable("invalid_worker_result")
            return unavailable(reason)
        probability = result.get("probability")
        score = result.get("risk_score")
        classification_threshold = result.get("classification_threshold")
        is_binary_v2 = result.get("contract_version") == "scythe_fusion_v2"
        if (result.get("availability") != "observed"
                or isinstance(probability, bool) or not isinstance(probability, (int, float))
                or not math.isfinite(probability) or not 0 <= probability <= 1
                or isinstance(score, bool) or not isinstance(score, (int, float))
                or not math.isfinite(score) or round(probability * 100, 2) != score
                or result.get("risk_level") not in {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
                or (is_binary_v2 != (classification_threshold is not None))
                or not all(isinstance(result.get(key), str) and result[key]
                           for key in ("model_version", "contract_version", "release_manifest_sha256", "model_sha256"))
                or any(not re.fullmatch(r"[0-9a-f]{64}", result[key])
                       for key in ("release_manifest_sha256", "model_sha256"))
                or (classification_threshold is not None and (
                    isinstance(classification_threshold, bool)
                    or not isinstance(classification_threshold, (int, float))
                    or not math.isfinite(classification_threshold)
                    or not 0 < classification_threshold < 1
                    or result.get("risk_level") != ("HIGH" if probability >= classification_threshold else "SAFE")))):
            return unavailable("invalid_worker_result")
        return result
    except Exception:
        return unavailable("worker_unavailable")


class RiskFusionEngine:
    """Attach evidence explanations to an isolated, release-verified prediction.

    A missing or failed release stays UNKNOWN. Alert tasks additionally enforce
    the unavailable flag and deduplicate incident creation under a scan row lock.
    """

    def compute(
        self,
        cyberintel: dict,
        browser_features: dict,
        sandbox_features: dict,
        consistency_report: dict,
        release_result: dict | None = None,
    ) -> dict:
        merged_features = {
            "cyberintel": cyberintel or {},
            "browser_features": browser_features or {},
            "sandbox_features": sandbox_features or {},
            "consistency_report": consistency_report or {},
        }

        result = release_result if release_result is not None else run_risk_fusion(merged_features)

        explanations = self._build_explanations(merged_features, result)

        return {
            **{key: result[key] for key in ("availability", "error_reason", "model_version", "contract_version",
                                            "release_manifest_sha256", "model_sha256", "elapsed_ms",
                                            "component_availability", "evidence_completeness",
                                            "classification_threshold") if key in result},
            "risk_score": result["risk_score"],
            "severity": result["risk_level"],
            "probability": result["probability"],
            "explanations": explanations,
            "iocs": merged_features["cyberintel"].get("iocs", []),
            # Propagated from run_risk_fusion() -- this is the field
            # tasks/risk_fusion.py's alert gate and log line both read.
            # Previously this key was never set on the dict this method
            # returns, so both of those silently no-op'd against a
            # missing key. Fixed here, not there -- this is the single
            # source of truth for "is the score real."
            "is_placeholder": result["is_placeholder"],
        }

    def _build_explanations(self, merged_features: dict, result: dict) -> list:
        explanations = []

        consistency_report = merged_features["consistency_report"]
        if consistency_report.get("cloaking_suspected"):
            explanations.append("Cloaking suspected: browser and sandbox views disagree.")

        mismatches = consistency_report.get("mismatches") or []
        if mismatches:
            explanations.append(f"Consistency mismatches: {', '.join(mismatches)}.")

        if result.get("is_placeholder"):
            explanations.append(
                "Validated model verdict unavailable; no safe classification can be inferred."
            )

        if consistency_report.get("reduced_confidence"):
            indeterminate = consistency_report.get("indeterminate_categories", [])
            explanations.append(
                f"Consistency score has reduced confidence "
                f"({', '.join(indeterminate) if indeterminate else 'some categories'} "
                f"not yet available)."
            )

        return explanations
