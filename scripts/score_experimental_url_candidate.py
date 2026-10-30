"""Score one URL with the frozen, non-release URL character candidate.

This diagnostic CLI intentionally returns a probability without converting it
to a phishing/benign verdict. The candidate failed the approved operating
policy and must not drive scan risk or incidents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
WORKSPACE = REPO.parent
ARTIFACT = WORKSPACE / "lightgbm_dataset" / "fresh" / "artifacts" / "url_character_dev_v2"
BACKEND = REPO / "containers" / "backend"
sys.path.insert(0, str(BACKEND))
# The dataset workspace vendors the already-pinned lightweight URL parsing
# dependency for host-side research scripts. Production uses backend pins.
sys.path.insert(0, str(WORKSPACE / "lightgbm_dataset" / "_deps"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verified_artifacts() -> tuple[dict, dict, dict]:
    if not ARTIFACT.is_dir():
        raise FileNotFoundError("experimental_model_artifact_missing")
    checksums = {}
    for line in (ARTIFACT / "checksums.sha256").read_text(encoding="ascii").splitlines():
        expected, name = line.split("  ", 1)
        if Path(name).name != name or name in checksums:
            raise ValueError("invalid_checksum_manifest")
        path = ARTIFACT / name
        if not path.is_file() or _sha256(path) != expected:
            raise ValueError("model_artifact_checksum_mismatch")
        checksums[name] = expected
    required = {"feature_contract.json", "threshold.json", "url_vectorizer.json", "url_linear_head.json"}
    if not required.issubset(checksums):
        raise ValueError("model_artifact_incomplete")
    contract = json.loads((ARTIFACT / "feature_contract.json").read_text(encoding="utf-8"))
    threshold = json.loads((ARTIFACT / "threshold.json").read_text(encoding="utf-8"))
    vectorizer = json.loads((ARTIFACT / "url_vectorizer.json").read_text(encoding="utf-8"))
    head = json.loads((ARTIFACT / "url_linear_head.json").read_text(encoding="utf-8"))
    if (contract.get("model_version") != "url_character_dev_v2"
            or contract.get("scoring_backend") != "url_char_tfidf_linear_v1"
            or contract.get("positive_label") != 1
            or threshold.get("release_activation") is not False
            or threshold.get("selection", {}).get("status") != "no_threshold_meets_validation_policy"):
        raise ValueError("unsupported_or_qualified_model_contract")
    return contract, threshold, {"vectorizer": vectorizer, "head": head}


def score_url(url: str) -> dict:
    from services.model_features.url_features import build_url_feature_vector
    from services.release_components import char_tfidf_probability

    common = {"model_version": "url_character_dev_v2", "status": "experimental_only"}
    observed = build_url_feature_vector(url)
    if observed.get("status") != "observed":
        return {**common, "availability": "unavailable", "probability": None,
                "reason": observed.get("reason", "invalid_http_url")}
    contract, threshold, payload = _verified_artifacts()
    probability = char_tfidf_probability(
        payload["vectorizer"], payload["head"], observed["canonical_url"],
        contract.get("feature_contract"),
    )
    return {**common, "availability": "observed", "probability": probability,
            "threshold": None,
            "diagnostic_threshold": threshold.get("threshold"),
            "diagnostic_threshold_use": "not an operating point; no threshold met policy",
            "feature_contract_version": contract["version"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="URL string to score; no network request is made")
    args = parser.parse_args()
    try:
        result = score_url(args.url)
    except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
        result = {"model_version": "url_character_dev_v2", "status": "experimental_only",
                  "availability": "unavailable", "probability": None,
                  "reason": str(exc) if str(exc) else "model_unavailable"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["availability"] == "observed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
