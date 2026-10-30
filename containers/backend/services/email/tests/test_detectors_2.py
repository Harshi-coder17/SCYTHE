"""Deterministic detector tests; no local mailbox dumps or network are used."""
from services.email.detectors.authentication_detector import AuthenticationDetector
from services.email.detectors.content_detector import ContentDetector


def test_authentication_failure_scores_above_verified_pass():
    detector = AuthenticationDetector()
    valid = detector.detect({"authentication": {"spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass", "alignment": "pass"}})
    failed = detector.detect({"authentication": {"spf_result": "fail", "dkim_result": "fail", "dmarc_result": "fail", "alignment": "fail"}})
    assert failed["score"] > valid["score"]
    assert failed["reasons"]


def test_content_detector_handles_absent_content_without_io():
    result = ContentDetector().detect({"metadata": {}, "content": {}})
    assert isinstance(result["score"], (int, float))
    assert 0 <= result["score"] <= 100
    assert isinstance(result["reasons"], list)
