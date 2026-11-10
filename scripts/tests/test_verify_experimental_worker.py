import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location("worker_verifier", Path(__file__).parents[1] / "verify_experimental_worker.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


@pytest.mark.parametrize("count", [8, 18])
def test_finalized_validation_size_is_not_hardcoded(count):
    rows = [{"capture_id": str(i)} for i in range(count)]
    expected = {(path, row["capture_id"]): 0.5 for row in rows for path in ("quick_url", "deep_url")}
    verifier.verify_reference_membership(rows, ("quick_url", "deep_url"), expected)


@pytest.mark.parametrize("defect", ["missing_path", "foreign_capture", "duplicate_capture"])
def test_reference_must_match_exact_finalized_membership(defect):
    rows = [{"capture_id": "a"}, {"capture_id": "b"}]
    expected = {(path, row["capture_id"]): 0.5 for row in rows for path in ("quick_url", "deep_url")}
    if defect == "missing_path":
        expected.pop(("deep_url", "a"))
    elif defect == "foreign_capture":
        expected[("quick_url", "foreign")] = 0.5
    else:
        rows.append({"capture_id": "a"})
    with pytest.raises(ValueError, match="membership_mismatch"):
        verifier.verify_reference_membership(rows, ("quick_url", "deep_url"), expected)
