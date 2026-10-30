"""Observed, contemporaneous v10 enrichment shared by training and inference."""
from datetime import datetime, timezone
import math


def extract_scythe_observations(observations, contract, capture_id, reference_time=None):
    """Return fixed-contract values plus availability; never infer missing safety.

    Offline evaluation passes the historical decision time. Runtime uses UTC now.
    Future, stale, unprovenanced, label-derived and mismatched-capture values are
    unavailable. The contract pins the provider/algorithm/unit for each feature.
    """
    names = {field["path"].split(".", 1)[1].removesuffix("_available")
             for field in contract.get("features", []) if isinstance(field, dict)
             and isinstance(field.get("path"), str) and field["path"].startswith("scythe.")}
    result = {key: value for name in names for key, value in ((name, None), (name + "_available", 0))}
    reference = reference_time if reference_time is not None else datetime.now(timezone.utc)
    if isinstance(reference, str):
        try:
            reference = datetime.fromisoformat(reference.replace("Z", "+00:00"))
        except ValueError:
            return result
    max_age = contract.get("evidence_max_age_seconds", 3600)
    if (not isinstance(reference, datetime) or reference.tzinfo is None
            or isinstance(max_age, bool) or not isinstance(max_age, (float, int))
            or not math.isfinite(max_age) or max_age < 0 or not isinstance(observations, dict)):
        return result
    for name in names:
        observation = observations.get(name)
        spec = contract.get("observation_specs", {}).get(name)
        if (not isinstance(observation, dict) or not isinstance(spec, dict)
                or any(not isinstance(spec.get(key), str) or not spec[key] for key in ("provider", "algorithm", "unit"))):
            continue
        try:
            observed_at = datetime.fromisoformat(observation.get("observed_at", "").replace("Z", "+00:00"))
            age = (reference - observed_at).total_seconds()
        except (TypeError, ValueError, AttributeError):
            continue
        available = (observation.get("status") == "observed" and observation.get("value") is not None
                     and observation.get("label_derived") is False and 0 <= age <= max_age
                     and bool(capture_id) and observation.get("capture_id") == capture_id
                     and all(observation.get(key) == value for key, value in spec.items()))
        if not available:
            continue
        value = observation["value"]
        if name == "ip_hosting_type":
            if not isinstance(value, str):
                continue
            value = contract.get("categorical_mapping", {}).get(name, {}).get(value)
        if (isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value)):
            continue
        result[name], result[name + "_available"] = value, 1
    return result
