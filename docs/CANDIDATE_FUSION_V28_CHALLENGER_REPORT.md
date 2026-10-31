# Candidate Fusion v28 Challenger Release Report

**Date**: October 31, 2026  
**Status**: `experimental_challenger` (Shadow Evaluation Only)  
**Production Trust Anchor**: `candidate_fusion_v26` (`6fe3b2e3a357967ee8b524fe26df645afb1e203ce93c485ec5468d0bf2b8fae1`)

---

## 1. Executive Summary

`candidate_fusion_v28` is an anti-leakage verified challenger release candidate engineered to establish rigorous cross-split domain independence. Both URL and Visual sub-models were trained on Azure Cloud compute using registered-domain `GroupShuffleSplit` partitioning with strict programmatic assertions enforcing zero domain overlap across train, validation, and test splits.

---

## 2. Model Architecture & Benchmark Metrics

### A. URL Classifier Sub-Head (`url_classifier_v28.txt`)
* **Architecture**: LightGBM GBDT (18-feature PaaS & lexical signal contract).
* **Dataset**: 100,000+ deduplicated URLs from UCI PhiUSIIL and URL-Phish.
* **Leakage Controls**: Domain-level `GroupShuffleSplit` across second-level registered domains.
* **Metrics**:
  * **Test ROC-AUC**: `0.9972`
  * **Test Recall**: `98.40%`
* **Artifact SHA-256**: `90591d70d21bb10299f471c92554188822dbf0f46325bc4770f852510db87550`

### B. Visual Classifier Sub-Head (`visual_classifier_v28.json`)
* **Architecture**: Apple MobileCLIP S0 (512-dim L2 embeddings) + balanced Logistic Regression head.
* **Dataset**: 7,389 authentic screenshots (1,552 phishing + 5,837 benign) across 4,382 unique registered domains.
* **Class Weighting**: `balanced` (inverse class frequency) to eliminate majority-class bias.
* **Split Partitioning**:
  * **Train**: 5,275 samples (24.0% phishing)
  * **Validation**: 793 samples (15.9% phishing)
  * **Test**: 1,321 samples (12.3% phishing)
* **Metrics**:
  * **Validation ROC-AUC**: `0.8241`
  * **Test ROC-AUC**: `0.8469`
  * **Test PR-AUC**: `0.6169`
  * **Test Recall**: `58.58%`
  * **Test Precision**: `46.84%`
  * **Test F1**: `0.5205`
* **Artifact SHA-256**: `bd8885edac24c0069f703806430eb16cb8cce275009c0e914f5b20b327af5532`

---

## 3. Governance & Artifact Manifest

All artifacts are staged in `models/releases/candidate_fusion_v28/`:

| File | SHA-256 Checksum | Purpose |
|:---|:---|:---|
| `url_classifier.txt` | `90591d70d21bb10299f471c92554188822dbf0f46325bc4770f852510db87550` | 18-feature URL classifier booster |
| `url_feature_contract.json` | `ce1d6440feb8ce0c05736e3eba77deffece3a4c16e3896c0c77ab6c8f8dea411` | Feature ordering & definitions |
| `visual_classifier.json` | `bd8885edac24c0069f703806430eb16cb8cce275009c0e914f5b20b327af5532` | MobileCLIP S0 logistic head weights |
| `visual_feature_contract.json`| `62a3a30ca5f8e0a492ffa9d742bae73a9b0b22c77ea8e8c3190ac04786619250` | 512-dim crop normalization spec |
| `approved_policy.json` | `99aada803711b9a6f3ba6e687c6b0745b9e0c79048a77538916b7b6a0ad02255` | Operational policy & thresholds |
| `release.json` | `25b7608e2daf2fe5f7d5ec298d72dfb4182ecf74577e2668cef0f337c03da683` | Metadata & supported model paths |
| `EXPERIMENTAL_DESIGNATION.md` | `3a759c0972fffa5ed3df3607f950c5eb5e343ab345344aefd68ea64e291d2ed4` | Shadow qualification protocol |
| `experimental_evaluation.json` | `18a6bf533768802422109c150eae2761dd48a601d368a3f21d3e75d11996dede` | Machine-readable benchmark report |
