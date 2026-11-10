# Multimodal v10 Paired Fusion Candidate Roadmap

## 1. Executive Summary & Objective

The project's authoritative v10 risk decision engine requires a multimodal fused model that combines URL features, visual features, contemporaneous threat intelligence enrichment, and sandbox execution signals. 

Existing URL and MobileCLIP models are component-level research artifacts. The first v10 fusion candidate, `scythe_fusion_v1`, has now been trained experimentally on 20 paired rows (14 train / 6 validation), but it is not qualified for real verdicts: validation PR-AUC and ROC-AUC are 0.50, and all 3 benign validation rows were false positives. 

Runtime risk scoring remains strictly fail-closed at `UNKNOWN` (heuristic/placeholder only, no automated incidents) until an experimental fusion candidate passes formal evaluation on a new, untouched independent holdout per `local_operational_model_policy_v1.json`.

---

## 2. Paired Multimodal Evidence Schema

The fusion trainer (`lightgbm_dataset/prospective_fusion.py`) requires records where all evidence streams are bound to the exact same `capture_id`:

```json
{
  "capture_id": "uuid-v4",
  "url": "https://example.com/login",
  "registrable_domain": "example.com",
  "label": 1,
  "synthetic": false,
  "source": "prospective_collection_v1",
  "split": "train",
  "captured_at": "2026-10-17T12:00:00Z",
  "decision_at": "2026-10-17T12:00:05Z",
  "label_evidence": { ... },
  "screenshot": { ... },
  "embedding": { ... },
  "scythe": { ... },
  "scan_evidence": { ... }
}
```

### Evidence Component Requirements

1. **URL & Feature Vector**:
   - Canonical URL string and 15 ordered features from `schema.json`.
2. **Screenshot & Visual Embedding**:
   - Decoded viewport $\ge 400 \times 250$ px.
   - Pinned MobileCLIP-S0 normalized 512-dimensional embedding. The current trainer verifies the checkpoint, encoder-source hashes, preprocessing version, and a single representation across all rows. It accepts `center` or `three_crop_mean`; choose and freeze one using training/validation evidence before any untouched holdout is scored. Full-width letterboxing is not a supported candidate in the current trainer. The crop audit found that alternate views are not drop-in replacements for the frozen v1 head; MobileCLIP v2 was separately trained with three-crop embeddings, so the audit does not reject that trained representation universally.
3. **Contemporaneous SCYTHE Enrichment**:
   - 8 predictors + 5 pivot fields (DNS, RDAP, InternetDB, hosting type, lookalike distance).
   - Observation timestamp must be within $\le 1\text{ hour}$ of capture time.
   - Explicit `_available` flag for each feature to track missingness without silent defaults.
4. **Browser & Sandbox Signals**:
   - DOM forms, scripts, links, password field counts, cross-domain form actions, cloaking detection, and consistency score.
5. **Independent Label Evidence**:
   - Every training/validation row needs documented, reviewer-attributed evidence and an explicit confidence class. Feed-supported and proxy-benign labels may be used only as clearly identified experimental supervision; they do not become independent ground truth. A `release_holdout` row must have independently supported historical evidence, independently of the label feed. Tranco rank or screenshot appearance alone cannot establish a benign label.

---

## 3. Current Cohort Status & Limitations

- **Prospective Cohort v2 (`lightgbm_dataset/prospective_collection_v1/cohort_v2`)**:
  - Contains 37 observed captures across 88 prospective attempts.
  - 20 captures pass conservative viewport-quality screening (11 proxy-benign, 9 feed-supported phishing).
  - All labels are development supervision; zero have independent release-label evidence. All 20 campaign identifiers are unknown.
  - The later 2026-10-17 collection run contains 8 candidate records; 4 capture statuses succeeded, 3 overlap the existing validation set, and only 1 successful capture is novel to that manifest. It is not yet part of the frozen fusion manifest.
- **Multimodal Paired Dataset (`lightgbm_dataset/prospective_v1`)**:
  - The checksummed paired manifest binds 20 URLs, screenshots, normalized MobileCLIP-S0 embeddings, timestamped SCYTHE observations, and feed/proxy label evidence. It is split into 14 train and 6 validation records, with no campaign IDs.
  - `scythe_fusion_v1` is fitted with five grouped out-of-fold component folds, but its six-row validation is not informative: PR-AUC 0.50, ROC-AUC 0.50, Brier 0.25, and 3/3 benign false positives. No test split or release holdout was scored.
  - Of the eight SCYTHE predictors, shortener use is present for 20/20, expiry for 18/20, and hosting type for 13/20. The other five predictors are unavailable for every row. All seven browser/sandbox signals are missing for 20/20 rows.
- **Release Gating & Remaining Gap**:
  - **Zero cohort rows currently possess independent release labels** (feed/proxy supervision only).
  - Historical benchmarks (Phishpedia, Phish360) remain development-only.
  - Runtime scoring remains strictly fail-closed at `UNKNOWN` until an independent release holdout ($\ge 5,000$ benign, $\ge 2,000$ phishing) is registered and evaluated.

---

## 4. Cohort Expansion Protocol

1. **Prospective Capture Execution**:
   - Use `lightgbm_dataset/prospective_collection_v1/collect_pilot.py` to capture live candidate sites through the isolated sandbox runner's passive browser mode.
   - Disposable research accounts authenticate scans; host browsers never visit candidate targets.
2. **Quality Screening**:
   - Run `finalize_cohort.py` to screen screenshots:
     - Exclude blank/expired/interstitial pages.
     - Quarantine dominant consent overlays.
3. **Domain-Grouped Partitioning**:
   - Partition records strictly by `registrable_domain` into `train`, `validation`, and `release_holdout`.
   - Ensure zero cross-split domain overlap.
4. **Fusion Training**:
   - Execute:
     ```powershell
     python lightgbm_dataset/prospective_fusion.py --manifest <paired.jsonl> --evidence-root <root> --train-output lightgbm_dataset/prospective_v1/artifacts/scythe_fusion_v1
     ```
   - `prospective_fusion.py` fits component heads on grouped training folds, trains fusion on out-of-fold component probabilities, and selects the threshold on validation only. It does not evaluate the reserved release holdout or approve runtime activation. The current code also requires the declared SCYTHE observation status/raw evidence for each feature and keeps unavailable observations null.

---

## 5. Release Qualification Gate

Before promoting the fusion candidate to active runtime scoring:
- **Untouched Holdout**: Minimum 5,000 benign and 2,000 phishing records with independent ground truth.
- **Operational Policy Targets (`local_operational_model_policy_v1.json`)**:
  - Recall $\ge 80\%$.
  - Benign False Positive Rate (FPR) $\le 1\%$.
  - p95 inference latency bounded on target worker hardware.
- **Fail-Closed Rule**: If any criterion is not met, runtime scoring remains at `UNKNOWN`.
