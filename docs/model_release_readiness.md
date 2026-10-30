# Experimental model release evidence

Run from the workspace containing SCYTHE, lightgbm_dataset and mobileclip-dataset:

```powershell
python SCYTHE/scripts/model_release_readiness.py --dataset-deps lightgbm_dataset/_deps --policy SCYTHE/docs/local_operational_model_policy_v1.json --output audit-output/model-release-readiness.json
python -m pytest SCYTHE/scripts/tests/test_model_release_readiness.py -q
```

`--workspace` is the parent of the `SCYTHE`, `lightgbm_dataset`, and
`mobileclip-dataset` directories. The CLI now rejects a repository root passed
as the workspace and records the resolved workspace in new reports. An audit
from the wrong directory must not be treated as artifact corruption.

The corrected 2026-10-19 audit is
`docs/model_readiness_20261019_corrected_workspace.json`. It verifies all 41
original bundle files and all three contracts. The frozen URL candidate's
155,609 training and 38,902 validation rows contain zero excluded URL/domain
hits and zero cross-split domains. The historical
`model_readiness_20261019_postcapture.json` was invoked with the repository as
the workspace; its two artifact/exclusion failures are invalid path findings.
It is retained unchanged for traceability. The corrected audit retains the
three substantive qualification blockers: untouched independent holdout,
immutable quality/latency evaluation, and validated fusion release bundle.
No frozen checksum manifest was regenerated.

Exit 2 is the expected blocked-production result for the current experimental stage. The command audits evidence without loading pickle/joblib objects, invoking providers, scoring another holdout, training, selecting thresholds, or changing runtime. A passing hash check does not certify model quality. The command intentionally cannot promote these experimental bundles on the strength of an API health response or an operator policy file alone.

The current local report is `audit-output/model-release-readiness-20261017.json`.
It lists three technical gates: no qualified untouched holdout, no immutable
quality/latency evaluation binding the frozen inputs, and no validated fusion
release bundle. The local quality policy is approved. Older reports retain
their historical blocker counts; they are not the current operational status.

The 2026-10-15 report verified 41 model-bundle checksums, the exact runtime URL feature order, both visual contracts (including the explicit frozen v1 legacy representation), and the candidate-time URL/domain exclusion files against 155,609 training plus 38,902 validation rows. There were zero excluded URL/domain hits and zero cross-split domains. Registered datasets added after a candidate was frozen cannot retrospectively become its untouched evaluation.

## Current limitations

- Both registered URL source acquisitions are explicitly development benchmarks, with zero independent historical label evidence coverage. Neither is an untouched release holdout. Their URLs/domains remain excluded from future selection/training through the existing registry.
- The already inspected visual external comparison favors v1 over v2: v1 recall 0.2825 with 528.94 false positives per 10,000 benign images; v2 recall 0.2565 with 638.72. These are raw selected-frame estimates, not deployment prevalence estimates. Design-weighted results and paired uncertainty remain in the JSON report.
- The earlier PhishVN failure evaluates lightgbm_fresh_v2, not the later lightgbm_dev_v2 candidate. The latter has development validation only. No new generalization claim follows from its validation score.
- The original visual training dataset includes 2,735 unknown-domain samples. Campaign separation is unverified, and the inspected visual source is not an after-model-run temporal evaluation. Some source licensing remains restricted/unclear.
- Existing DNS/RDAP/InternetDB observations cover 1,000 domains and 1,326 rows, collected retrospectively. They stay diagnostic and cannot be silently joined into training. Missing providers remain unavailable; no OTX credential was present in the reviewed configuration. Re-querying the same historical cohort does not repair historical feature freshness or label provenance.
- The newest URL-only experimental candidate, `lightgbm_prospective_url_v1`, has 109,209 training and 27,457 validation rows, with validation PR-AUC 0.9802. Its manifests preserve confidence/source strata and known evaluation exclusions. This does not establish external generalization or supply the contemporaneous nine-feature SCYTHE dataset and fusion model still needed. Any expanded representation requires a new contract and version.
- Encoder extraction throughput is measured, but production request p95 latency is not established. Cold/warm validation, preprocessing, inference and artifact access must be measured on the intended worker.
- The owner has now accepted the local policy in `local_operational_model_policy_v1.json`: recall at least 80%, benign false positives at most 1%, confidence-bound acceptance, bounded latency, UNKNOWN on failure, and v10 local actions. No additional permission prompt is required. These are targets, not achieved performance.

## Next release evaluation

`local_model_release_evaluation_protocol_v2.json` governs new release evaluations;
the historical v1 protocol is retained. A protocol registration does not itself
establish independently labelled data. Acquire independently evidenced
historical labels and documented capture dates; establish URL/domain/image
exclusions; checksum the evidence; register noninspection; then freeze model,
threshold, policy and protocol hashes before scoring once. Retain failed results.
Any examined holdout becomes a development benchmark for later decisions.

Fresh DNS/RDAP/InternetDB collection is technically available without paid credentials, but it is justified for a prospectively timestamped new training cohort after source/label/exclusion eligibility is established. Retrospective collection cannot recover historical DNS/certificate/hosting states. Do not use label-feed membership as a predictor. There is no arbitrary waiting interval in this protocol; a daily temporal comparison needs its actual time boundary documented.

The implementation now includes a separate model queue, native release loader,
candidate scorer, independent evaluator, immutable bundle builder, and verified
local startup. New work uses `local_model_release_evaluation_protocol_v2.json`
and the commands in `local_model_release.md`. Existing v1 protocol/evaluation
artifacts retain their historical meaning. Without a passing bound release,
ordinary model verdicts remain UNKNOWN and cannot trigger incidents. Code
integration does not supply the missing paired training or independent holdout
evidence.

Real prospective collection has begun: the saved pilot reports contain 16
observed captures across 32 attempts, including timestamped raw enrichment and
explicit capture/provider failures. No pilot row currently has an independent
release label. The new source-acquisition inventory records checksummed paired
assets, source licences, capture-date gaps, and prior-domain/image overlap before
any model scoring or split assignment. These are data-collection results, not
model-quality measurements. See the sibling acquisition and prospective
collection directories for record-level provenance.
