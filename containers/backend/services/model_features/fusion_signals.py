"""Finite numeric v10 browser/sandbox/consistency evidence shared with training."""
import math

SIGNALS = {
    "browser_dom_form_count": (0, None),
    "browser_dom_script_count": (0, None),
    "browser_dom_link_count": (0, None),
    "sandbox_password_field_count": (0, None),
    "sandbox_cross_domain_form_count": (0, None),
    "consistency_score": (0, 1),
    "consistency_cloaking_suspected": (0, 1),
}


def extract_scan_signals(browser_features=None, sandbox_features=None, consistency_report=None):
    browser = (browser_features or {}).get("dom") or {}
    sandbox = sandbox_features or {}
    forms = sandbox.get("form_metrics") or {} if sandbox.get("sandbox_available", True) else {}
    consistency = consistency_report or {}
    raw = {
        "browser_dom_form_count": browser.get("forms"),
        "browser_dom_script_count": browser.get("scripts"),
        "browser_dom_link_count": len(browser["links"]) if isinstance(browser.get("links"), list) else None,
        "sandbox_password_field_count": forms.get("password_field_count"),
        "sandbox_cross_domain_form_count": forms.get("cross_domain_form_count"),
        "consistency_score": consistency.get("consistency_score"),
        "consistency_cloaking_suspected": int(consistency["cloaking_suspected"])
            if type(consistency.get("cloaking_suspected")) is bool else None,
    }
    # A partial consistency result cannot silently become an observed full score.
    if consistency.get("reduced_confidence") is True:
        raw["consistency_score"] = None
        raw["consistency_cloaking_suspected"] = None
    result = {}
    for name, (minimum, maximum) in SIGNALS.items():
        value = raw[name]
        observed = (not isinstance(value, bool) and isinstance(value, (int, float))
                    and math.isfinite(value) and value >= minimum
                    and (maximum is None or value <= maximum))
        result[name] = value if observed else None
        result[name + "_available"] = int(observed)
    return result
