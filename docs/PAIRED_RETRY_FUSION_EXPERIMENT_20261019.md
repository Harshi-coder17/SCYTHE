# Reviewed retry-cohort fusion experiment

A complete **experimental** `scythe_fusion_v2` was trained locally on actual
paired capture evidence. It is not eligible for activation. The independent
release-label count remains zero.

The latest trained revision is v6, described in the follow-ups below. A prior
revision is `lightgbm_dataset/prospective_reviewed_dev_v4` and
`lightgbm_dataset/prospective_reviewed_dev_v4_fusion_v2`. Older revisions below
are retained as historical results. Version 4 corrects a verified sandbox-export
defect using original saved raw metadata, without changing labels, images,
partitions, or protected exclusions.

## Data and lineage

The immutable sources are runs `20261018T195641362974Z`,
`20261018T210056446558Z`, and `20261018T211900909257Z`: 201 retained attempts
covering 144 distinct targets. Failed attempts remain in history; a targeted
retry replaces its predecessor in training selection. No historical source
files, reviewer decisions, or checksum manifests were rewritten.

The machine quality screen accepted 40 screenshots (14 feed-supported phishing,
26 Tranco proxy controls). One was excluded because its redirect/domain touched
the protected registry, leaving 39 paired development samples: 14 phishing and
25 proxy benign. A screenshot-quality judgment does not independently verify
the historical phishing/benign label. All annotations retain explicit machine
attribution and `independent_label_adjudication=not_done`.

The connected grouping covers registrable domains, observed redirect domains,
known campaigns when verified, exact screenshots, and 64-bit grayscale dHash
distance at most six. Missing campaigns remain unknown. The deterministic
80/20 target produces 31 training records (20 benign/11 phishing) and eight
validation records (five benign/three phishing). There are 19 benign and ten
phishing connected training groups. The source/class distributions are recorded;
class and source remain strongly confounded in this small sample.

## Evidence and training

`lightgbm_dataset/prospective_reviewed_dev_v3/` includes the source attempt
history, actual scan JSON, screenshot/embedding evidence, timestamped provider
observations, exact builder/trainer source snapshots, dependency versions, and
checksums. `captured_at` and `decision_at` come directly from the saved scan
evidence. No artificial offset or historical enrichment backfill is used.
Observations lacking provider/timestamp/algorithm/unit evidence remain null.
Actual browser, sandbox, and consistency observations supply the seven scan
signals with availability indicators.

Coverage is partial: all 39 records have the three browser predictors;
`sandbox_available=false` and partial consistency results leave the four
sandbox/consistency predictors unavailable. SCYTHE predictor coverage is 39/39
URL-shortener observations, 27/39 domain-expiration observations, and 14/39
hosting-type observations. The other five predictors remain unavailable. The
presence of the complete contract does not imply complete observed evidence.
Those sandbox counts describe version 3's original export interpretation.
In version 4, 37/39 rows recover the two actual sandbox form-count predictors.
The saved normal successful metadata omitted `sandbox_available`; the legacy
collector had incorrectly defaulted the missing field to false. Recovery checks
raw source checksums, `scans.request_id` against the actual capture `scan_id`,
the requested URL, valid nonempty form metrics, and bounded execution timestamps.
Two rows lack a saved sandbox completion timestamp and remain unavailable.
Explicit false, null, malformed flags, unbound IDs and late evidence fail closed.
Derived evidence is labeled in provenance and includes separate unchanged
original scan JSON and sandbox metadata references. No new observation was
collected retrospectively. The consistency reports remain reduced-confidence
because OCR/logo comparisons were indeterminate; their two features remain
unavailable rather than being upgraded to full confidence.

The pinned CPU FP32 MobileCLIP-S0 encoder creates normalized three-crop-mean
embeddings. Cache keys include the image checksum, checkpoint/reference,
encoder source, preprocessing source hashes, precision, and representation.
Cache payload hashes are checked before reuse. Incomplete interrupted entries
are preserved separately and recomputed; corrupt complete entries fail closed.
The invocation retains a six-hour extraction checkpoint budget.

`lightgbm_dataset/prospective_reviewed_dev_v3_fusion_v2/` contains the completed
native quick/deep boosters, safe JSON component coefficients/vocabulary/IDF,
33-column contract, threshold findings, five-fold OOF predictions, component
comparison, metrics, dependency locks, and SHA-256 manifest. Training uses
quick/deep views weighted 0.5 each, grouped OOF component predictions, and
training-only fitted transforms. The first class-complete training-label/group
partition uses fold seed 43, selected deterministically from bounded seeds
42..141 without consulting model scores or validation performance. Seed 42's
heuristic grouped split omitted a class from one held fold despite sufficient
class groups; that diagnostic failure was retained in the implementation notes.

Selected components are character TF-IDF logistic regression (`C=0.1`) and the
frozen S0 three-crop image head (`C=0.01`). On only eight development-validation
records, quick fusion PR-AUC is **0.7917**, deep fusion PR-AUC **0.9167**. These
tiny selected-validation estimates do not establish generalization.

**Neither path has a policy-feasible threshold.** With five benign validation
records, even zero observed false positives has a 95% Wilson FPR upper bound
of **43.45%**, far above the required 1%. The saved finite conservative fallback
threshold detects zero of three phishing images; it is explicitly infeasible,
not a deployable operating point. Undefined precision is null. No policy target
was relaxed and no previously examined holdout was relabeled as independent.

The earlier `prospective_reviewed_dev_v1` and `prospective_reviewed_dev_v2`
cohorts/candidates remain untouched.
Version 2 preserves the same selected data and split, adds exact source/dependency
snapshots, and corrects the threshold report's zero-detection precision from
zero to null. This is a reporting/reproducibility revision, not additional
training evidence or an improved quality claim.

Version 3 repairs a runtime contract defect found while preparing the latency
benchmark: raw evidence uses `algorithm_version`, while runtime observation
extraction expects the contract key `algorithm`. The trainer now explicitly
maps the raw-evidence specification into the runtime schema. Older experimental
candidate revisions must not be activated: their runtime would mark observed
enrichment unavailable despite its use during training. The underlying reviewed
data, split, thresholds, and policy are unchanged. A regression test exercises
real runtime observation extraction instead of merely reconstructing an already
formed feature vector.

## Verification and remaining gates

All 75 dataset tests pass, including retry selection, preserved attempts,
checksum corruption, conflict quarantine, deterministic connected splitting,
visual/redirect group isolation, safe embedding reuse, fold class coverage,
and infeasible threshold handling. Ruff passes for changed dataset files.
Native booster reload predictions match exactly on all eight validation rows.
The separate `prospective_reviewed_dev_v2_verification` output recorded actual
runtime encoder/component/vector parity on those same development images, but
did not cover the observation-extraction stage. The final version 3 development
latency benchmark additionally verifies actual `score_one` observation/signal
extraction against the training matrix for both paths before measuring repeated
warm inference. Neither report is untouched qualification evidence.
The benchmark ran during concurrent Docker/Trivy and collection work; host load
was not controlled. Its repeated timing and descriptive uncertainty cannot
certify production-worker p95 latency.

The saved `prospective_reviewed_dev_v3_latency_v1/benchmark.json` records 32
warm scores per path across the eight already inspected validation inputs,
with zero scoring failures. Quick p50/p95 are **26.47/31.79 ms**; deep p50/p95
are **1,730.37/2,445.29 ms**. The descriptive bootstrap intervals for p95 are
30.43–32.01 ms quick and 2,014.13–3,058.18 ms deep; repeated inputs and concurrent
host workloads limit their interpretation. The single cold observation records
8.70 seconds of module imports, 1.97 seconds of artifact validation/native model
loading, and 10.06 seconds of encoder loading. These are separate stages, not
an asserted complete cold-start distribution. Hardware was Windows AMD64,
14 logical CPUs, eight Torch threads, and one LightGBM prediction thread.
All sixteen actual quick/deep observation/signal extraction checks matched the
training matrix before timing. Measurements cover input/artifact validation,
preprocessing and inference; they exclude queueing, capture and provider delays.

Version 4 was independently rechecked as a development revision in
`prospective_reviewed_dev_v4_latency_v1/benchmark.json`: 16 actual quick/deep
feature-extraction parity checks passed, followed by 32 warm scores per path
with zero unavailable results. Quick p50/p95 were **14.33/23.53 ms** and deep
**853.98/1,053.81 ms**. Descriptive p95 bootstrap intervals were 19.54–28.73 ms
quick and 975.17–1,303.92 ms deep. Single cold stages were 6.32 seconds of
imports, 1.96 seconds of artifact/native-model load, and 10.99 seconds of
encoder load. The benchmark explicitly records uncontrolled concurrent project
workloads. Neither the faster measurements nor recovered sandbox predictors
change the failed threshold finding or qualify the candidate for activation.

This experiment resolves the absence of a recently trained complete paired
candidate. Remaining qualification work is substantial: larger and more diverse
paired development data, independently supported labels, an after-freeze untouched
2,000-phishing/5,000-benign domain-group holdout, path-specific quality and
availability evaluation, production-worker latency, verified release packaging,
and local activation/workflow testing. Runtime scoring remains fail-closed;
no trained experimental probability changes incidents or user risk levels.

## Version 5: expanded reviewed development cohort

`lightgbm_dataset/prospective_reviewed_dev_v5` and
`lightgbm_dataset/prospective_reviewed_dev_v5_fusion_v2` were finalized on
2026-10-19 from eight immutable collection runs and six quality-review sources.
The merge retains 567 attempts covering 358 canonical targets. After quality,
conflict, protected-domain/redirect exclusions and deduplication, 86 captures
remain: 23 feed-supported phishing and 63 proxy benign. The grouped split has
68 training records (18 phishing/50 benign) and 18 validation records
(5 phishing/13 benign). Training has 13 phishing and 49 benign connected groups.
All labels remain development supervision; independently adjudicated release
labels remain zero. Original v1-v4 artifacts and source records are preserved.

The completed historical-source 200-attempt run supplied 42 screenshots. Offline
quality review accepted 31 proxy-benign captures, left six pending and excluded
five; neither of its two observed feed-positive pages passed quality review.
The source selection was an IP-heavy bounded pool, so its low yield must not be
presented as an unbiased estimate for the entire historical feed.

Version 5 uses five-fold component predictions, seed 42, 136 weighted quick/deep
training views, and the same 33-column contract. Native model reload predictions
match exactly on all 18 validation records for both paths. Validation PR-AUC is
0.88333 quick and 0.96667 deep. These are selected development estimates on a
different split from v4 and are not a controlled improvement comparison.

Neither path has a feasible deployment threshold. Even zero false positives
among 13 benign validation examples has a Wilson upper bound of 22.81%, above
the required 1%. The explicitly infeasible conservative fallback detects zero
of five phishing examples. The candidate remains experimental and unactivated;
additional independent data is required, not a relaxed gate.

## Version 6: fresh OpenPhish captures

The latest trained revision is now `prospective_reviewed_dev_v6` with candidate
`prospective_reviewed_dev_v6_fusion_v2`. The additional finalized 36-target
OpenPhish/control run supplied 16 screenshots. Quality review accepted eight
feed-positive and four proxy-benign captures, excluded three, and left one
pending. This yields 98 eligible development captures (31 phishing/67 benign),
split into 79 training records (25/54) and 19 validation records (6/13).
Original v5 and earlier artifacts remain immutable.

Both selected paths have validation PR-AUC 1.0 on these 19 records. This is a
tiny selected development split with source/class confounding (OpenPhish versus
Tranco), not evidence of deployment performance. Both saved thresholds remain
explicitly infeasible under the Wilson false-positive constraint. No independent
release labels, release evaluation, or model activation was created.

The actual normal worker and beat were rebuilt with authenticated-backup code
at a drained collection checkpoint. Restore verification into a disposable
PostgreSQL database passed on the normal worker after a verified backup-volume
ownership correction. This is operational evidence, not model qualification.
The 106-target collection resumed its same frozen selection after worker health
checks. Its in-progress records are excluded from this frozen v6 training run.
