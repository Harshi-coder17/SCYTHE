from services.model_features.fusion_signals import extract_scan_signals


def test_signal_adapter_preserves_observed_zero_and_distinguishes_missing():
    result = extract_scan_signals({"dom": {"forms": 0, "scripts": 5, "links": ["/login"]}},
                                  {"form_metrics": {"password_field_count": 1}},
                                  {"consistency_score": .7, "cloaking_suspected": False})
    assert result["browser_dom_form_count"] == 0
    assert result["browser_dom_form_count_available"] == 1
    assert result["browser_dom_link_count"] == 1
    assert result["sandbox_cross_domain_form_count"] is None
    assert result["sandbox_cross_domain_form_count_available"] == 0
    assert result["consistency_cloaking_suspected"] == 0
    assert result["consistency_cloaking_suspected_available"] == 1


def test_partial_or_failed_evidence_is_unavailable():
    result = extract_scan_signals({"dom": {"forms": -1, "scripts": True}},
                                  {"sandbox_available": False, "form_metrics": {"password_field_count": 0}},
                                  {"consistency_score": 1, "cloaking_suspected": False, "reduced_confidence": True})
    assert all(value is None or value == 0 for value in result.values())
    assert result["sandbox_password_field_count"] is None
    assert result["consistency_score"] is None
