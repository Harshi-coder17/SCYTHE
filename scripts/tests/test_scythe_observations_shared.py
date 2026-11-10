import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[2] / "containers/backend/services/model_features/scythe_observations.py"
SPEC = importlib.util.spec_from_file_location("scythe_observations", PATH)
shared = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shared)

CONTRACT = {"features": [{"path": "scythe.domain_expiration_duration"}, {"path": "scythe.domain_expiration_duration_available"}, {"path": "scythe.ip_hosting_type"}], "evidence_max_age_seconds": 3600,
            "observation_specs": {"domain_expiration_duration": {"provider": "RDAP", "algorithm": "expiry_v1", "unit": "days"}, "ip_hosting_type": {"provider": "ASN", "algorithm": "type_v1", "unit": "category"}},
            "categorical_mapping": {"ip_hosting_type": {"hosting": 2}}}


def observation():
    return {"provider": "RDAP", "algorithm": "expiry_v1", "unit": "days", "status": "observed", "value": 42, "label_derived": False, "capture_id": "capture", "observed_at": "2026-10-01T00:00:00Z"}


def test_observed_historical_enrichment_and_default_missing_values():
    result = shared.extract_scythe_observations({"domain_expiration_duration": observation()}, CONTRACT, "capture", "2026-10-01T00:05:00Z")
    assert result["domain_expiration_duration"] == 42
    assert result["domain_expiration_duration_available"] == 1
    assert result["ip_hosting_type"] is None and result["ip_hosting_type_available"] == 0


@pytest.mark.parametrize("key,value", [("capture_id", "other"), ("label_derived", True), ("provider", "other"), ("algorithm", "other"), ("unit", "other"), ("value", float("nan")), ("value", True), ("observed_at", "2026-10-01T00:06:00Z"), ("observed_at", "2026-09-30T00:00:00Z"), ("observed_at", "2026-10-01T00:00:00")])
def test_invalid_stale_future_or_mismatched_values_are_unavailable(key, value):
    row = observation()
    row[key] = value
    result = shared.extract_scythe_observations({"domain_expiration_duration": row}, CONTRACT, "capture", "2026-10-01T00:05:00Z")
    assert result["domain_expiration_duration"] is None
    assert result["domain_expiration_duration_available"] == 0


def test_categorical_mapping_is_fixed_and_unknown_values_are_unavailable():
    row = {**observation(), **CONTRACT["observation_specs"]["ip_hosting_type"], "value": "hosting"}
    result = shared.extract_scythe_observations({"ip_hosting_type": row}, CONTRACT, "capture", "2026-10-01T00:05:00Z")
    assert result["ip_hosting_type"] == 2
    row["value"] = "unknown"
    result = shared.extract_scythe_observations({"ip_hosting_type": row}, CONTRACT, "capture", "2026-10-01T00:05:00Z")
    assert result["ip_hosting_type"] is None
