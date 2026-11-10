# SCYTHE model qualification progress — 2026-10-19

## Result

SCYTHE is **not production-model qualified**. The local runtime remains fail-closed; no candidate was promoted or activated. This update records collection and verification work without treating feed labels, Tranco rank, or screenshot appearance as independent ground truth.

## Paired-capture continuation

Three append-only runs cover 144 unique selected targets: 44 feed-listed phishing candidates and 100 Tranco proxy controls. The 57-row targeted retry repeats targets from the first run and is not counted as additional unique data.

| Unique target outcome | Feed-listed phishing | Tranco proxy controls | Total |
|---|---:|---:|---:|
| Captured, quality review pending | 30 | 50 | 80 |
| Near-uniform quality exclusion | 1 | 2 | 3 |
| Unavailable | 13 | 48 | 61 |
| **Unique targets** | **44** | **100** | **144** |

There are **zero independently adjudicated release labels**. The 80 captured screenshots therefore remain pending human quality review and cannot yet be called verified training examples. The three near-uniform screenshots are excluded. The 61 unavailable outcomes remain in the manifest. After retrying only the 57 known token-expiry failures, 42 remaining capture failures were `CaptureUnavailable`, 14 were `UnsafeURL`, one was a capture-command timeout, and four were fresh capture-command failures; no further retries were made.

Each run retained a score-free review queue. The queues have 123, 57, and 21 rows, respectively, with 719, 409, and 128 verified evidence references. All checksum manifests verified without missing files or mismatches (729, 419, and 137 entries). All three temporary collection accounts were disabled. DNS/RDAP/InternetDB coverage was 93.5%/80.6%/90.5% for the first run, 94.7%/77.2%/92.1% for the targeted retry, and 71.4%/76.2%/100% for the continuation. These are collection diagnostics, not model qualification evidence.

Run artifacts:

- `lightgbm_dataset/prospective_collection_v1/runs/20261018T195641362974Z/`
- `lightgbm_dataset/prospective_collection_v1/runs/20261018T210056446558Z/`
- `lightgbm_dataset/prospective_collection_v1/runs/20261018T211900909257Z/`

Each contains `collection_report.json`, `paired_records.jsonl`, `review_queue.json`, `review_batches/`, `checksums.sha256`, and cleanup/provenance records.

## Candidate and runtime status

Existing URL and MobileCLIP candidates remain experimental. The current paired material is far below the required development cohort and contains no independent labels; it cannot support a valid 33-column fusion model or its quick/deep qualification. No synthetic records were added to training data, no threshold was tuned against an external cohort, and no release bundle was activated.

The runtime review fixed a fail-closed validation gap for malformed unavailable worker responses and tightened frozen-threshold and checksum identity checks. The runtime agent reports 56 focused backend tests and 17 release/scoring tests passing, plus lint and syntax checks. A local workflow smoke passed on existing containers, but those containers predate the latest working-tree edits. A host-side full backend test attempt could not collect because the host Python environment lacks project dependencies (`tldextract` among them); it is not evidence of a product test failure or a passing full-suite run.

The explicit-policy readiness audit is saved at `docs/model_readiness_20261019_postcapture.json`. It reports `production_ready: false` with five outstanding gates:

1. Frozen bundle hash/contract verification is incomplete.
2. Candidate exclusion and domain-split verification has not passed.
3. No registered, independently labeled, domain-disjoint untouched holdout is available.
4. No immutable evaluation binds the approved policy, frozen artifacts, untouched data, and measured production latency.
5. No validated final risk-fusion release bundle exists.

The frozen operational policy remains unchanged: recall Wilson lower bound ≥80%, false-positive Wilson upper bound ≤1%, at least 2,000 phishing and 5,000 benign independent domain groups per path, full supported-input availability, and warm p95 latency ≤2 seconds for quick and ≤15 seconds for deep scans.

## Next work

1. Human-review the 80 captured images for screenshot quality using the score-free batches; make no label decisions from appearance alone.
2. Obtain independent evidence tied to each specific URL and capture, then have actual reviewers record decisions. Keep unresolved cases quarantined.
3. Expand prospective paired collection substantially, preserving domain/campaign/visual grouping and the established protected-domain exclusions.
4. Train and freeze a complete fusion candidate only after there is sufficient reviewed development data; then collect a new untouched holdout and evaluate once against the unchanged policy.
5. Rebuild containers from the latest source and rerun the full local workflow and security checks before any local activation.

Human label adjudication and a sufficiently large untouched holdout cannot be manufactured by code or substituted with synthetic data. Until those gates pass, unavailable predictions must remain `UNKNOWN` and model-driven incidents remain disabled.
