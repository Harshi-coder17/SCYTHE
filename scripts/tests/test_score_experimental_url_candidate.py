import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import score_experimental_url_candidate as scorer  # noqa: E402


def test_experimental_scorer_returns_probability_without_verdict():
    result = scorer.score_url("https://example.com/login")
    assert result["availability"] == "observed"
    assert result["status"] == "experimental_only"
    assert 0 <= result["probability"] <= 1
    assert result["threshold"] is None
    assert "label" not in result


def test_invalid_input_is_unavailable_not_zero_risk():
    result = scorer.score_url("javascript:alert(1)")
    assert result["availability"] == "unavailable"
    assert result["probability"] is None


def test_artifact_tampering_is_rejected(monkeypatch, tmp_path):
    (tmp_path / "checksums.sha256").write_text("bad  classifier.json\n", encoding="ascii")
    (tmp_path / "classifier.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(scorer, "ARTIFACT", tmp_path)
    try:
        scorer._verified_artifacts()
    except ValueError as exc:
        assert str(exc) == "model_artifact_checksum_mismatch"
    else:
        raise AssertionError("modified model artifact was accepted")
