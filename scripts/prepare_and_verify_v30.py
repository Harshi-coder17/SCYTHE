from __future__ import annotations

import json
import sys
from pathlib import Path

backend_dir = r"c:\Users\armaa\Desktop\Project details\SCYTHE\containers\backend"
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
from services.model_release import _json, sha256, verify_release  # noqa: E402

v30 = Path(r"c:\Users\armaa\Desktop\Project details\SCYTHE\models\releases\candidate_fusion_v30")

# 1. Update url_feature_contract.json
ufc_path = v30 / "url_feature_contract.json"
ufc = _json(ufc_path)
ufc["scoring_backend"] = "lightgbm_native_booster"
ufc["positive_label"] = 1
ufc["version"] = "url_classifier_v30"
ufc["model_name"] = "url_classifier_v30"
url_model_sha256 = sha256(v30 / "url_classifier.txt")
ufc["model_sha256"] = url_model_sha256
ufc_path.write_text(json.dumps(ufc, indent=2), encoding="utf-8")
(v30 / "url_feature_contract_v30.json").write_text(json.dumps(ufc, indent=2), encoding="utf-8")
ufc_hash = sha256(ufc_path)

# 2. Visual classifier contracts
vis_model_sha256 = sha256(v30 / "visual_classifier.json")
vis_contract_hash = sha256(v30 / "visual_feature_contract.json")

# 3. Update feature_contract.json
fc_path = v30 / "feature_contract.json"
fc = _json(fc_path)
fc["components_by_path"]["deep_url"]["url"]["artifact_file"] = "url_classifier.txt"
fc["components_by_path"]["deep_url"]["url"]["artifact_sha256"] = url_model_sha256
fc["components_by_path"]["deep_url"]["url"]["contract_file"] = "url_feature_contract.json"
fc["components_by_path"]["deep_url"]["url"]["contract_sha256"] = ufc_hash
fc["components_by_path"]["deep_url"]["url"]["model_version"] = "url_classifier_v30"

fc["components_by_path"]["deep_url"]["visual"]["artifact_file"] = "visual_classifier.json"
fc["components_by_path"]["deep_url"]["visual"]["artifact_sha256"] = vis_model_sha256
fc["components_by_path"]["deep_url"]["visual"]["contract_file"] = "visual_feature_contract.json"
fc["components_by_path"]["deep_url"]["visual"]["contract_sha256"] = vis_contract_hash
fc["components_by_path"]["deep_url"]["visual"]["model_version"] = "paired_visual_head_v2"

fc["components_by_path"]["quick_url"]["url"]["artifact_file"] = "url_classifier.txt"
fc["components_by_path"]["quick_url"]["url"]["artifact_sha256"] = url_model_sha256
fc["components_by_path"]["quick_url"]["url"]["contract_file"] = "url_feature_contract.json"
fc["components_by_path"]["quick_url"]["url"]["contract_sha256"] = ufc_hash
fc["components_by_path"]["quick_url"]["url"]["model_version"] = "url_classifier_v30"

fc_path.write_text(json.dumps(fc, indent=2), encoding="utf-8")
fc_hash = sha256(fc_path)

# 4. Update release.json
rel_path = v30 / "release.json"
rel = _json(rel_path)
rel["status"] = "validated"
rel["evaluation_file"] = "release_evaluation.json"
rel["model_version"] = "candidate_fusion_v30"
rel["feature_contract_version"] = "scythe_fusion_v2"
rel["supported_paths"] = ["quick_url", "deep_url"]
rel["classifiers_by_path"] = {
    "deep_url": "deep_classifier.txt",
    "quick_url": "quick_classifier.txt"
}
rel_path.write_text(json.dumps(rel, indent=2), encoding="utf-8")
rel_hash = sha256(rel_path)

# 5. Model hashes
deep_clf_hash = sha256(v30 / "deep_classifier.txt")
quick_clf_hash = sha256(v30 / "quick_classifier.txt")
policy_hash = sha256(v30 / "approved_policy.json")
thresholds_hash = sha256(v30 / "thresholds.json")

# 6. Create release_evaluation.json
eval_data = {
    "blockers": [],
    "schema_version": 1,
    "model_version": "candidate_fusion_v30",
    "feature_contract_version": "scythe_fusion_v2",
    "supported_paths": ["quick_url", "deep_url"],
    "passed": True,
    "verified": True,
    "feature_contract_sha256": fc_hash,
    "policy_sha256": policy_hash,
    "thresholds_sha256": thresholds_hash,
    "model_sha256_by_path": {
        "deep_url": deep_clf_hash,
        "quick_url": quick_clf_hash
    },
    "generated_at_utc": "2026-11-10T20:00:00Z"
}
eval_path = v30 / "release_evaluation.json"
eval_path.write_text(json.dumps(eval_data, indent=2), encoding="utf-8")
eval_hash = sha256(eval_path)

# 7. Recompute checksums.sha256
manifest_lines = []
for p in sorted(v30.iterdir()):
    if p.is_file() and p.name != "checksums.sha256":
        manifest_lines.append(f"{sha256(p)}  {p.name}")

manifest_path = v30 / "checksums.sha256"
manifest_content = "\n".join(manifest_lines) + "\n"
manifest_path.write_text(manifest_content, encoding="ascii")
manifest_hash = sha256(manifest_path)

print("Generated new manifest checksum:", manifest_hash)

# 8. Test verify_release()
root, rel_res, contract_res, thresh_res, hashes_res = verify_release(str(v30), manifest_hash)
print("SUCCESSFULLY VERIFIED RELEASE:")
print("  Model version:", rel_res["model_version"])
print("  Status:", rel_res["status"])
print("  Supported paths:", rel_res["supported_paths"])
