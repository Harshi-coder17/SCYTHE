# Local model release

The owner accepted the local deployment plan and its operational targets in the
current project conversation. `local_operational_model_policy_v1.json` records
that acceptance. An additional permission prompt is not a technical release gate.
No current research model is promoted by this policy.
New evaluations use `local_model_release_evaluation_protocol_v2.json`; the
historical v1 protocol remains available with its original decisions.

## Current evidence

Both registered external URL snapshots are development benchmarks. The second
registration reports 14,342 domains overlapping existing datasets and independent
label-evidence coverage of zero. Previously evaluated PhishVN, Phish360, and
external screenshots are also development evidence. They cannot certify a new
release. Existing trained models remain useful for diagnosis and shadow scoring.

## Freeze and score

1. Create a new registration using
   `model_release_templates/release_registration_v2.template.json`. Bind the
   approved policy, classifier, contract, thresholds, scorer source, protocol,
   cohort, exclusion registry, and independently reviewed historical evidence by
   SHA256 before running inference. Populate attestation fields honestly.
2. Include at least 5,000 independently supported benign and 2,000 phishing
   records. Preserve source and actual capture timestamps. Every record needs
   a canonical URL, verified registrable domain, and evidence tied to the same
   historical capture. Tranco rank or screenshot appearance alone is not evidence
   of a benign/phishing label. Visual paths additionally require a checksummed image.
3. Exclude all known training/validation/test and examined development URL/domain,
   campaign, and visual groups. The exclusion JSON contains `canonical_urls`,
   `registrable_domains`, `campaign_groups`, `visual_groups`, and `source_manifests`
   (each source has `path` and `sha256`). Include known campaign/visual groups;
   describe unknown campaigns explicitly in the registration limitations.
4. Run preflight without predictions. A passing registration still exits 2 because
   release predictions are not available. It must never activate models.
5. Run `scripts/score_release_candidate.py` once, preserving each sample for each supported path,
   including unavailable results. Do not tune the threshold against this cohort.
6. Evaluate into a new output version. Existing output directories are refused.
   Archive failed evaluations; examined cohorts become development benchmarks for
   future model decisions. New release claims need a new untouched cohort.

```powershell
python scripts/model_release_evaluation.py --registration <registration.json> --dataset-deps ..\lightgbm_dataset\_deps --output-dir <new-preflight-directory>
python scripts/model_release_evaluation.py --registration <registration.json> --predictions <predictions.json> --dataset-deps ..\lightgbm_dataset\_deps --output-dir <new-evaluation-directory>
```

`thresholds.json` has strictly ordered `safe`, `low`, `medium`, `high` fractions.
`medium` is the frozen HIGH/action decision boundary. These values must come from
training/validation selection; this evaluator never chooses them.

The cohort JSONL contains `sample_id`, `label` (0 benign, 1 phishing),
`canonical_url`, `registrable_domain`, `captured_at_utc`, `source`, optional
`campaign_group` and `visual_group`, and `image: {path, sha256}` for deep scans.
Evidence JSONL contains the same identity, URL, label and capture timestamp plus
`independent: true`, `observed_at_utc`, `basis`, and `evidence: {path, sha256}`.
Allowed evidence bases are `historical_publisher_adjudication`,
`documented_site_owner_control`, and `independent_historical_analysis`; an
independent reviewer must assess authenticity before registration. Paths are
resolved relative to the containing manifest.

The predictions JSON contains `metadata` and `records`. Metadata binds
`model_sha256`, `feature_contract_sha256`, `thresholds_sha256`, `holdout_sha256`,
`registration_sha256`, and `source_code_sha256`, and declares `started_at_utc`,
`target_hardware`, and
`warm_latency_includes_preprocessing_validation_inference: true`. Each record
contains `sample_id`, `path` (`quick_url` or `deep_url`), `status`
(`available`/`unavailable`), `probability` (null when unavailable), and `elapsed_ms`.

Generate these probabilities with the real candidate scorer; do not construct
them manually. Registration `source_code` must bind that scorer's exact source
and `runtime_source_sha256` must pin the five shared runtime modules listed in
the v2 template. Candidate checksum anchoring and descriptor verification occur
before any holdout input reaches inference. A persistent isolated process enforces
the 60-second input deadline and returns unavailable on timeout or worker failure.

```powershell
python scripts/score_release_candidate.py --registration <registration.json> --candidate-dir <candidate-directory> --candidate-checksums-sha256 <recorded-candidate-sha256> --encoder-source-dir ..\mobileclip-dataset --dataset-deps ..\lightgbm_dataset\_deps --training-warmup <warmup-manifest.json> --output-dir <new-prediction-directory>
```

Use a trusted Python environment with the candidate's pinned LightGBM,
MobileCLIP/PyTorch, image, and offline PSL dependencies. The scorer does not
download models or install packages. The warmup manifest has
`role: training_warmup` and `record: {path, sha256}` pointing to a training record
with the same input schema. Warmup URLs/domains/campaign/visual groups must be
disjoint from the holdout. Warmup is never included in metrics and model
parameters do not change. Without successful separate training warmup, all
latencies remain explicitly cold or unverified and the report cannot pass the
warm-latency release gate. Worker initialization time is reported separately.

Optional cohort `scan_evidence: {path, sha256}` binds historical browser, sandbox,
consistency, and SCYTHE observations to matching `capture_id` in both the row and
evidence JSON. `decision_at_utc` defaults to the capture timestamp, must be between
capture and registration, and is the shared enrichment helper's freshness
reference. Values observed after that decision, label-derived values, stale
values, and provider/algorithm/unit mismatches remain unavailable. Missing
required contract inputs produce unavailable predictions. No live verdict,
incident, threshold selection, or activation occurs in this command.

## Gate and package

For every supported path, recall's 95% Wilson lower bound must reach 0.80 and
false-positive rate's upper bound must stay at or below 0.01. All registered
inputs count: unavailable phishing inputs are missed detections, and any
unavailable input fails required 100% supported-path coverage. Warm request p95
must stay within 2 seconds for quick URL scoring and 15 seconds for deep scoring;
no inference request may exceed the 60-second task limit.

The report includes confusion counts, precision, recall, F1, PR average precision,
ROC-AUC, false positives per 10,000 benign, Brier score, ECE10/reliability bins,
source breakdown, coverage, and latency. Wilson intervals assume independent
observations: domain/campaign dependence and provenance uncertainty must be
retained as limitations. Calibration reporting does not establish calibration.

Package a passing report as `release_evaluation.json` alongside `release.json`,
`classifier.txt`, `feature_contract.json`, `approved_policy.json`, and
`thresholds.json`; checksum every file. Record the checksum-manifest hash as an
explicit configuration trust anchor. A hash establishes integrity, not a model's
validity or a label's truth. No illustrative/synthetic test fixture is release
evidence.

Use the tested staging builder rather than assembling a release by hand. It
verifies the pinned candidate and bound evidence, calls the runtime verifier,
and only then renames staging to a new final version. It does not enable models.

```powershell
python scripts/build_model_release.py --candidate-dir <candidate-directory> --candidate-checksums-sha256 <recorded-candidate-sha256> --evaluation <release_evaluation.json> --policy docs/local_operational_model_policy_v1.json --thresholds <frozen-thresholds.json> --output <new-release-directory>
```

```powershell
python scripts/model_release_readiness.py --workspace .. --dataset-deps ..\lightgbm_dataset\_deps --release-bundle <release-directory> --release-checksums-sha256 <recorded-sha256> --output <readiness-report.json>
```

Current functionality can be deployed locally while release scoring remains
unavailable. Missing release evidence must never be converted into zero risk or
silently remove the model quality gate.
