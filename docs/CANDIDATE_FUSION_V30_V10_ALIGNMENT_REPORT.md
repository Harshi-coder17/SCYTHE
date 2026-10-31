# Candidate Fusion v30: V10 Specification Alignment & Challenger Report

**Release**: `candidate_fusion_v30`  
**Date**: October 31, 2026  
**Status**: `experimental_challenger` (Unified V10 Specification Culmination)  
**Reference Document**: `PROJECT_v10.pdf` (Pages 7, 10, & System Architecture)  
**Production Baseline**: `candidate_fusion_v26` (`6fe3b2e3a357967ee8b524fe26df645afb1e203ce93c485ec5468d0bf2b8fae1`)

---

## 1. Architectural Alignment with `PROJECT_v10.pdf`

`candidate_fusion_v30` synthesizes the model evolution milestones (v26, v27, v28) into the canonical multi-tier architecture mandated by `PROJECT_v10.pdf`:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PROJECT_v10.pdf PIPELINE                         │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │   STAGE 1: QUICK SCAN (v10 Page 7: schemas/quick_scan)   │
       │   • 18-Feature Lexical & PaaS LightGBM (from v28/v27)   │
       │   • ROC-AUC: 0.9972 | Recall: 98.40% | Latency: <5ms     │
       └─────────────────────────────────────────────────────────┘
                                    │
                         (Score >= Threshold / Deep Path)
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │   STAGE 2: SANDBOX DETONATION (v10 Page 7: sandbox_analysis)│
       │   • Headless Chromium Screenshot Capture (256x256 Crop) │
       │   • MobileCLIP S0 512-dim L2 Embeddings (from v28)      │
       │   • 53,620 Master Vision Head (ROC-AUC: 0.9615)         │
       └─────────────────────────────────────────────────────────┘
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │   STAGE 3: CELERY CHORD (v10 Page 10)                   │
       │   chord([header_task, url_task, attach_task, vision_task│
       │        ])(consistency_task)                             │
       └─────────────────────────────────────────────────────────┘
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │   STAGE 4: CONSISTENCY ENGINE (v10 Page 7)              │
       │   • Cross-validates Visual Brand vs SSL Hostname vs DOM │
       └─────────────────────────────────────────────────────────┘
                                    │
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │   STAGE 5: RISK FUSION (v10 Page 7: risk_fusion.py)     │
       │   • 32-Feature Calibrated Multimodal Booster (from v26) │
       │   • Wilson 95% Confidence Bounds (SAFE / BLOCKED)       │
       └─────────────────────────────────────────────────────────┘
```

---

## 2. Synthesis of Technical Milestones

| Component | Provenance | Technical Contribution | Key Metric |
|:---|:---|:---|:---|
| **Fast URL Classifier** | `v28` | 18 lexical & cloud platform indicators (Vercel, Supabase, Cloudflare Pages) | **0.9972 ROC-AUC**, **98.40% Recall** |
| **Expanded Vision Head** | `v30` (53K) | Apple MobileCLIP S0 across 53,620 representations (Phish360, Zenodo, Fleet, PhishEval) | **0.9236 ROC-AUC**, **89.00% Recall**, **78.3% Precision** |
| **Neural MLP Vision Head** | `v30` (53K) | 2-Layer Neural MLP Head (512 $\to$ 128 $\to$ 32 $\to$ 1) with LayerNorm + GELU + Dropout | **0.9615 ROC-AUC**, **0.9456 PR-AUC**, **91.4% Precision**, **0.8816 F1**, **5.80% FPR** |
| **PaaS Threat Signatures** | `v27` | Subdomain heuristics targeting developer PaaS infrastructure abuse | 100% High Risk on `phantom-app-4eu8.vercel.app` |
| **Multimodal Fusion Engine** | `v26` | 32-feature booster linking URL, DOM, and Vision with Wilson 95% intervals | Sub-600ms p95 latency, 100% availability |
| **Leakage Controls** | `v28` | Strict second-level registered domain `GroupShuffleSplit` | **0 overlapping domains** across train/val/test |

---

## 3. Cryptographic Manifest (`checksums.sha256`)

All artifacts for `candidate_fusion_v30` are stored and sealed in `models/releases/candidate_fusion_v30/`:

```
99aada803711b9a6f3ba6e687c6b0745b9e0c79048a77538916b7b6a0ad02255  approved_policy.json
3cf80d7ed345d0a99e3eb67294714d27ae469461870dc34be88524e8663ad76c  deep_classifier.txt
ba6bf30556c24eab5b3c9e4eca4f9ebddd3558bb659f80592b1a61d31ba80b1f  EXPERIMENTAL_DESIGNATION.md
7b29cd8632a5decbcb34bdafcf5f2d229b09e86dcfd3b5071300759a0797d632  experimental_evaluation.json
d36cb2932c428620007a212f518832af42ffa3638878ca643cbabfe5373a67c7  feature_contract.json
bd7d8438671c32a43a13504da2bdd1b469ccb06c57ff0657167e93e594d80036  quick_classifier.txt
df3e0dd2682fdd4caf54cc59fbf687f2d7223bd47a1ca7e29dd8667c660400eb  release.json
1edc808fac75f2c5f3852b5394d281acafe0baa7ed88e5a6628e31ae25d5c443  threshold.json
1edc808fac75f2c5f3852b5394d281acafe0baa7ed88e5a6628e31ae25d5c443  thresholds.json
90591d70d21bb10299f471c92554188822dbf0f46325bc4770f852510db87550  url_classifier.txt
90591d70d21bb10299f471c92554188822dbf0f46325bc4770f852510db87550  url_classifier_v30.txt
ce1d6440feb8ce0c05736e3eba77deffece3a4c16e3896c0c77ab6c8f8dea411  url_feature_contract.json
ce1d6440feb8ce0c05736e3eba77deffece3a4c16e3896c0c77ab6c8f8dea411  url_feature_contract_v30.json
fc7a0ca5efac00ca6e4602f8c75808f8d520b5815bd2f953e9b9b5b5e903af55  visual_classifier.json
5f167b7207a77ce59a33bb767d56d2a2ae853540fa9012ddd722045f3f988a28  visual_classifier_22k.json
fc7a0ca5efac00ca6e4602f8c75808f8d520b5815bd2f953e9b9b5b5e903af55  visual_classifier_expanded.json
bd8885edac24c0069f703806430eb16cb8cce275009c0e914f5b20b327af5532  visual_classifier_v30.json
24da63cec75af6f16543ea5c14b6bb07d87ca3fa7ed2c82af19a98eac1387398  visual_classifier_v30_neural.json
62a3a30ca5f8e0a492ffa9d742bae73a9b0b22c77ea8e8c3190ac04786619250  visual_feature_contract.json
1033e65b50123ae3cdd8efaf86a94c802e629000a369d4f93425034611daa85b  visual_mlp_expanded.pt
```
