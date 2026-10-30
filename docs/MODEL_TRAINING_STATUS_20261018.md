# SCYTHE model training and local release status — 2026-10-18

## Result

An experimental MobileCLIP-S0 v4 visual head was trained from cached, frozen three-crop embeddings. It combines the unchanged v3 training split (9,289 rows) with 1,702 grouped PhishingEval/APWG phishing screenshots. The validation set contains the unchanged 2,011-row v3 validation split plus 397 domain/image-group-held-out PhishingEval screenshots (2,408 total). PCA was not used; balanced L2 logistic-regression heads with `C ∈ {0.01, 0.1, 1, 10}` were compared, and `C=10` was selected by validation PR-AUC.

The candidate is saved at `mobileclip-dataset/artifacts/mobileclip_v4_phishingeval_dev_v1/`. Its bundle records the exact training and validation manifests, dataset and encoder references, input embedding checksums, classifier, threshold, metrics, package lock, and checksums. The training script checks domain/image disjointness for the added fold, verifies cached normalized embeddings, and confirms serialized-head prediction parity. It reuses only cached encoder outputs; the encoder and existing v1–v3 bundles were not changed.

At its experimental validation F1 threshold (**0.4025**), v4 achieved PR-AUC **0.9667**, ROC-AUC **0.9661**, recall **93.7%**, and **1,367 false positives per 10,000 benign samples** (158/1,156). Brier score was **0.0720** and 10-bin ECE **0.0179**; these are descriptive and do not establish calibrated probabilities. At a validation operating point constrained to at most 1% empirical FPR, recall fell to **58.8%** (736/1,252), which misses the approved 80% minimum. A 5% empirical FPR point reached 82.2% recall but still corresponds to 493 false positives per 10,000, far above the approved maximum of 100.

These are development metrics, not release metrics. The PhishingEval source had already been examined in the v3 development diagnostic, is phishing-only, and contains 2021–2023 captures. Its labels and captures cannot supply the required untouched, current, two-class release holdout. The broader v3 diagnostic had 3,097 eligible rows, of which 998 could not be scored under the frozen image-input contract; those rows remain unavailable/misses in that earlier diagnostic and were not used to train v4. PhishingEval's archive is documented in the [official paper](https://www.usenix.org/system/files/usenixsecurity25-ji.pdf) and [Zenodo record](https://zenodo.org/records/14804193). Preserve their attribution and review the record's license/underlying-source terms before redistribution.

## Production decision

**No model is production-ready, and v4 is not connected to runtime scoring.** The approved policy in `docs/local_operational_model_policy_v1.json` requires recall ≥80%, no more than 100 false positives per 10,000 benign records, 95% confidence bounds, at least 2,000 phishing and 5,000 benign examples, complete supported-path coverage, a later untouched independently labeled holdout, p95 latency evidence, and a validated full v10 fusion bundle. V4 fails the observed false-positive/recall tradeoff and is a visual component only; it does not contain SCYTHE enrichment or browser/sandbox signals.

The readiness check at `../../audit-output/model-release-readiness-20261018-after-mobileclip-v4.json` verified candidate exclusion checks and research-bundle checksums, then reported these remaining release gates:

1. Register a genuinely untouched, later two-class holdout with independently supported historical labels, required counts, domain exclusions, and documented campaign uncertainty. Every currently registered candidate is explicitly a development benchmark.
2. Freeze a complete candidate and contract, score that holdout once, and pass the policy's recall/FPR confidence bounds, supported-input coverage, and p95 latency limits. Do not use the PhishEval, PhishVN, Phish360, starter, or other previously inspected cohorts as release evidence.
3. Train/evaluate a complete v10 fusion bundle with contemporaneous, non-synthetic component observations and real browser/sandbox scan signals. The current paired cohort is too small and lacks these signals.

Until those gates pass, preserve fail-closed runtime behavior: unavailable inputs remain `UNKNOWN`, and experimental model output must not affect severity, warnings, incidents, or automated actions. Further training on already inspected or positive-only data cannot turn this run into a qualified release.

## Verification

- v4 training completed on local CPU from frozen cached embeddings; no full encoder re-extraction occurred.
- Candidate checksum manifest: **14 files verified, no mismatches**.
- Python byte-compilation and Ruff passed for the new training script.
- `mobileclip-dataset/test_mobileclip_baseline.py` and `mobileclip-dataset/test_validation_audit.py`: **7 passed**.
- Readiness audit exit status is non-ready by design; the final report lists three release blockers after verified dataset exclusion checks.
- Runtime model configuration, fusion behavior, placeholder flags, alerts, and incident behavior were not changed.
