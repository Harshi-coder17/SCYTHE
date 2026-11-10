# Model qualification progress — 2026-10-18

## Decision

**There is still no production-qualified model.** The approved policy requires, for each supported quick/deep path, a 95% Wilson recall lower bound of at least 80%, a 95% Wilson false-positive upper bound of at most 1%, at least 2,000 independently supported phishing and 5,000 independently supported benign examples, full input coverage, and path-specific latency qualification. Current candidates are development-only and runtime scoring remains fail-closed.

The current readiness audit is [`model-release-readiness-20261018-after-urlchar.json`](../../audit-output/model-release-readiness-20261018-after-urlchar.json). It reports three unresolved gates: no untouched independently labeled holdout, no immutable passing release evaluation bound to model/data/policy/latency, and no validated complete v10 fusion bundle.

## URL model experiment

Trained `url_character_dev_v2` on the frozen `dataset_dev_v4` training split using character TF-IDF 3–5-grams and balanced L2 logistic regression. The vocabulary, IDF and head are JSON artifacts; no pickle is needed. All training and validation URLs were checked against SCYTHE's runtime canonicalizer. The run manifest records the training-script hash and package versions.

On the already-inspected 46,273-row development validation split, PR-AUC was **0.8937** and ROC-AUC **0.9696**. No threshold met both recall and false-positive policy bounds. The best recall at a threshold with the 95% Wilson false-positive upper bound at or below 1% was **62.9%** (4,388/6,979; Wilson lower bound **61.7%**), with 352 false positives among 39,294 development negatives. This is far below the 80% recall lower-bound requirement. The default diagnostic median threshold instead produces 4,133 false positives per 10,000 benign-labeled rows and is not an operating threshold.

For comparison, the existing LightGBM v4 validation has PR-AUC **0.7816**; at its best point under the same Wilson FPR upper bound it recalls **47.2%** (Wilson lower bound **46.0%**). The source/class-weighted candidate was worse on development PR-AUC (**0.7560**) than the balanced baseline (**0.7816**). These comparisons favor the character model for further development, but none meet release policy or establish external generalization.

The native no-pickle runtime component was added behind an explicit descriptor and checksum contract, with tests comparing its results to sklearn. Thirty-two real candidate URLs matched with maximum probability delta `2.83e-8`; warm local component p95 was **121 ms** over 20 calls. That is component-only timing: it excludes the API, task queue, capture, enrichment and full scan workflow. The component is not in an active release bundle.

Artifacts and diagnostics:

- [`url_character_dev_v2`](../../lightgbm_dataset/fresh/artifacts/url_character_dev_v2/)
- [`url_character_dev_v2_operating_point.json`](../../lightgbm_dataset/fresh/diagnostics/url_character_dev_v2_operating_point.json)
- [`lightgbm_multisource_url_dev_v4_operating_point.json`](../../lightgbm_dataset/fresh/diagnostics/lightgbm_multisource_url_dev_v4_operating_point.json)
- Training script: [`train_url_character_dev_v1.py`](../../lightgbm_dataset/train_url_character_dev_v1.py)
- Reproduction/threshold diagnostics: [`diagnose_url_character_dev_v1.py`](../../lightgbm_dataset/diagnose_url_character_dev_v1.py)

## Corrected source eligibility

The corrected audits separate prior training domains, which may be reused for training after deduplication, from protected validation/test/temporal and registered evaluation domains.

- PhiLegit-100K has **32,451** rows eligible for possible training after protected-domain exclusions: **22,404 publisher-labeled phishing and 10,047 benign** rows across sources. Most are already-known training domains; its source/class mixture is strongly confounded, labels are not independently re-adjudicated per row, and the 8 novel benign domains cannot support validation. It is not a holdout.
- URL-Phish v2 has **54,429** rows eligible for possible training after protected exclusions: 51,477 benign proxy rows and 2,952 feed-reported phishing rows. Almost all domains already appear in prior training; only one domain per class is new to prior training and protected evaluation sets. It is not a holdout.
- Reports: [`PHILEGIT_AUDIT.md`](../../dataset-acquisition/philegit_100k_source_v1/PHILEGIT_AUDIT.md), [`URL_PHISH_V2_AUDIT.md`](../../dataset-acquisition/url_phish_v2_source/URL_PHISH_V2_AUDIT.md); corrected machine-readable audits are `audit_v5/source_audit.json` and `audit_v3/source_audit.json` respectively.

The latest OpenPhish/Tranco snapshot contains 275 feed-listed URLs and 100,000 proxy-benign controls. PhishTank returned HTTP 429, so the collector did not retry it outside its bounded fetch policy. All 100,275 records overlap already protected evaluation URLs/domains; the pilot selected zero eligible targets and made no site captures. The result is recorded as `no_eligible_candidates` in [`20261017T214049784986Z`](../../lightgbm_dataset/prospective_collection_v1/runs/20261017T214049784986Z/collection_report.json). The collector now supports two isolated capture jobs, four concurrent provider requests, six-hour invocation budgets, and resumable checkpoints, but a new non-overlapping snapshot is needed before that pipeline can collect a useful cohort.

PhiShark is still not an input to this run: the dataset page says its 23.97 GB archive is restricted, and its page currently lists 53,591 observations while the accompanying paper describes 67,502 scans. Resolve the release/version and obtain approved access before importing or assigning it any training/holdout role. [Dataset access page](https://phishark2026dataset.com/), [paper](https://arxiv.org/abs/2608.23199).

## Existing visual and fusion status

MobileCLIP v4 was already trained from frozen three-crop embeddings and added PhishingEval phishing examples. Its validation result at 1% empirical FPR has only **58.8% recall**; it misses the approved operating policy. It is an inspected development result, not a release candidate. The v10 fusion model cannot be trained responsibly until there are enough same-capture records with screenshots, HTML, browser/sandbox signals and contemporaneous enrichment, split by domain/campaign/visual duplicates, and independently supported labels.

## Follow-up work — 2026-10-18

- Fetched another OpenPhish/Tranco snapshot (`20261017T222228352418Z`). It again contained 275 feed URLs and 100,000 Tranco controls; all 275 positive domains remain excluded by the protected-evaluation registry. A derivation over the retained full Tranco million-entry ranking added 5,000 previously unused control domains (`20261017T222255760981Z`, records SHA-256 `15531fae20e6e6ee7988e284c1b326d0746919df714aef99a0389c162c5ad14f`). These remain Tranco/feed-absence proxies and do not increase independently supported benign counts. No new phishing candidates were eligible.
- Ran the corrected isolated capture preflight on 100 of those proxy controls (`prospective_collection_v1/runs/20261017T222946886893Z`). It completed after a six-hour checkpoint and resumable continuation: **46 captures observed, 54 unavailable; 43 need human quality review and 3 are near-uniform**. The 100 records span 100 registrable domains, but campaign identity is unverified. DNS was observed for 80/100 domains, RDAP for 74/100, and InternetDB returned 99 observed responses among 114 IP queries (15 errors). The run has 462 checksum entries. The score-free offline review queue contains 100 records and 456 screenshot/HTML/redirect/provider references; every reference checksum validated. All labels are Tranco proxies; independent release labels remain **0**. These records have not been merged into a training split. [Review queue](../../lightgbm_dataset/prospective_collection_v1/runs/20261017T222946886893Z/review_queue.json).
- Corrected the PhiLegit prose arithmetic: 32,451 potentially eligible rows are 22,404 phishing plus 10,047 benign. The underlying audit already had the correct per-source row counts.
- Fixed the native URL scorer to use the 100,000 feature cap from the checksum-bound model contract, since the frozen vectorizer JSON records the fitted vocabulary and IDF but omits the cap field. The scorer now accepts that exact artifact shape and still rejects vocabulary sizes above the declared cap. On 32 canonical URLs, its probabilities matched sklearn with maximum absolute difference `5.01e-9`.
- Hardened prospective collection resumption with run-ID validation, source/exclusion checksum checks, preservation of existing reviewer decisions, and request-local HTTP sessions for concurrent providers. Added a separate 33-column `scythe_fusion_v2` contract/matrix implementation: quick views mask screenshot, enrichment and browser signals; deep views include only recorded observations. This is schema/data preparation only; no v2 fusion model has been trained or activated.

The refreshed readiness audit is [`model-release-readiness-20261018-final.json`](../../audit-output/model-release-readiness-20261018-final.json). It now inventories all URL candidates, including the character TF-IDF model and LightGBM versions, but remains non-ready for three concrete reasons: no registered independently labeled untouched holdout, no passing immutable evaluation bound to model/data/policy/latency, and no validated final fusion bundle. Local Docker services are healthy and `docker compose config --quiet` passes; that does not qualify a model.

## Verification performed

- Corrected source-audit scripts and URL model scripts: Ruff and Python compilation passed.
- Prospective collection integrity and resumable-selection tests: **7 passed**.
- LightGBM dataset tests: **56 passed**.
- Backend release-component tests, including the new checksum-bound character model scorer: **9 passed**.
- After follow-up changes, LightGBM/fusion dataset tests: **58 passed**; prospective collection integrity tests: **11 passed**; backend release-component and model-release tests: **30 passed**; release-builder/evaluation tests: **25 passed**; readiness-audit tests: **7 passed**. Changed code passed Ruff and Python compilation.
- MobileCLIP dataset/audit checks: **17 passed**. The host-only MobileCLIP inference test could not import pinned `timm`; the locked Docker shadow worker then scored a real validation screenshot successfully with MobileCLIP v1. This is a scorer smoke test, not a path-specific release evaluation.
- Local infrastructure is reachable at `https://localhost:8443`, but `model_worker_profile=false`; this does not verify the full model worker or browser-to-model workflow.
- The readiness audit exits non-ready by design. No model was activated, no policy threshold was relaxed, and no incident behavior changed.

## Remaining release gates

1. Obtain or collect a post-freeze, domain-disjoint holdout with independently supported labels for every included example, at least 2,000 phishing and 5,000 benign groups per path, and a registration/checksum manifest before any scoring.
2. Build a larger contemporaneous paired cohort for training the complete `scythe_fusion_v2` quick/deep paths. Historical or retrospective enrichment and Tranco absence cannot substitute for same-capture observations or verified benign labels.
3. Freeze the complete component/fusion bundle, thresholds, preprocessing, dependencies and policy before one-time holdout scoring. Include model failures in coverage and recall denominators.
4. Pass both path-specific Wilson bounds, coverage, calibration reporting and complete local workflow latency budgets; then build/verify a release bundle and exercise rollback. Until then, `UNKNOWN`/unavailable behavior stays active and no model-driven incidents are enabled.

No synthetic training labels were created. Synthetic fixtures remain useful for software tests only; they cannot supply the real-world evidence needed to qualify this model.

## Implementation follow-up — 2026-10-18

The prospective workflow now includes a v2 fusion trainer and corresponding disabled-by-default release support. The trainer produces grouped five-fold out-of-fold URL/visual component predictions; compares the 15-feature LightGBM and fold-local character TF-IDF URL heads plus the visual logistic-regression grid; masks visual and late signals from the quick path; and writes checksum-bound experimental artifacts. Runtime/release code verifies component contracts and auxiliary TF-IDF files. The package builder still rejects experimental thresholds, and no candidate is activated.

The refreshed source snapshot `20261018T095216006202Z` yielded a derived pool of 5,075 development candidates: 75 feed-listed phishing URLs and 5,000 Tranco controls. Existing project exclusions removed 1,048 phishing URLs/domains and 103,185 controls. Tranco absence remains a proxy label. PhishStats supplied 9 of 10 requested pages before HTTP 429; it was stopped rather than retried beyond the bounded collection policy. Its terms prohibit redistribution of raw feed data without written permission, so these records are retained locally only. See the [PhishStats API documentation](https://phishstats.info/api-docs) and [terms](https://phishstats.info/terms).

The isolated capture preflight `20261018T102651709069Z` completed all 141 eligible attempts (66 feed-labeled phishing and 75 Tranco controls): 23 phishing and 33 benign-proxy captures were observed; 43 and 42 respectively were unavailable. Of 56 observed images, 53 need human quality review and 3 are near-uniform. All 141 rows remain `split=unassigned`; independent release-label count is zero. One score-free review batch contains 141 records. A generated [run checksum manifest](../../lightgbm_dataset/prospective_collection_v1/runs/20261018T102651709069Z/checksums.sha256) verifies 867 run files; all 392 directly referenced capture/evidence files checked, with zero missing files or hash mismatches. Provider coverage was DNS 120/141 (85.1%), RDAP 102/141 (72.3%), and InternetDB 164/172 (95.3%). These are contemporaneous diagnostic observations, not evidence of independent labels or release eligibility.

Verification after the implementation: dataset tests **62 passed**; collection integrity tests **16 passed**; release builder/scorer/evaluation tests **36 passed**; backend release loader/component tests **34 passed** with a temporary test-only stub because the host interpreter lacks the pinned `tldextract` package. Ruff checks and Python compilation passed. The existing running Docker stack returned HTTP 200 for the local root and HTTP 401 for unauthenticated `/api/scans`; its disabled model inference returned `UNKNOWN`, unavailable, null probability, and no automatic decision. The stack was not rebuilt from the new source edits and has no model worker profile enabled.

The updated [readiness report](../../audit-output/model-release-readiness-20261018-training-release.json) still has three release blockers: no untouched independently labeled holdout, no immutable passing release evaluation, and no validated complete fusion release bundle. The new captures are a collection preflight, not enough reviewed data to train the paired candidate. Full quick/deep inference, incident behavior, and rollback were therefore not exercised with an active model. No threshold was relaxed, and no data or model was promoted.

## Experimental local URL scorer follow-up — 2026-10-18

Added [`score_experimental_url_candidate.py`](../scripts/score_experimental_url_candidate.py) so the best available URL-only head can be exercised locally without activating it in SCYTHE. It verifies every model-file checksum before inference, uses the same pinned no-pickle scorer and URL feature helper as the release worker, makes no network requests, emits `availability=unavailable` with a null probability for invalid input, and deliberately returns no class decision or operating threshold. Added tests cover scoring, invalid input, and artifact tampering.

This makes the experimental URL component runnable; it does not make it production-ready. The frozen character candidate's validation PR-AUC is 0.8937, but it does not satisfy the policy threshold bounds; its PhishVN comparison remains development-only. A CLI smoke check produced probabilities 0.0318 for `https://www.google.com/` and 0.9983 for `https://example.com/login`, demonstrating why these values must not be treated as verdicts or user-facing risk. The full fusion model remains untrainable from the current reviewed paired cohort: only 19 quality-approved captures were reported, no independent release labels were adjudicated, and the quick/deep holdout gates remain unmet.

Validation of this follow-up: the three scorer tests pass; Ruff and Python compilation pass. Example command: `python scripts/score_experimental_url_candidate.py "https://www.google.com/"` from the `SCYTHE` directory. The regular runtime remains fail-closed and unchanged.

## Expanded capture preflight — 2026-10-18

The transient retry path was exercised against the seven `backend_capture_command_failed` rows from run `20261018T102651709069Z`; it recovered one observed screenshot and recorded the other six as failed again. The recovered image remains `needs_review`. No retry was made for `CaptureUnavailable` or `UnsafeURL` outcomes. The disposable collection account was disabled after capture.

The fresh feed fetch was corrected to forward query parameters to the source adapter. Snapshot `20261018T122453831324Z` contained 562 feed-listed URLs and 10,000 Tranco controls. The exclusion-aware derived pool `20261018T122507817897Z` contains 65 eligible feed-listed phishing candidates and 5,000 Tranco proxy controls after protected-domain and URL exclusions; the remaining Tranco records were excluded as previously seen. Tranco remains a proxy label and current feed membership is source evidence, not independent adjudication.

The subsequent isolated preflight `20261018T122523763464Z` selected 139 candidates after excluding prior pilot domains: 39 phishing feed rows (37 OpenPhish and 2 PhishStats) and 100 Tranco controls. The isolated runner completed all attempts with 81 observed pages (30 phishing, 51 control) and 58 unavailable captures. Quality status is 77 `needs_review`, 4 `near_uniform`, and 58 unavailable. The 77 pending images cannot be accepted into training until quality review; the four near-uniform images are quality exclusions. Independent label adjudication remains **0/139**. The 139-row review batch contains no score/prediction fields, and no reviewer identity or decision has been inserted automatically. A checksum manifest verified all **1,042** listed run files with zero mismatches; **1,035** review references were verified by the collector. DNS coverage was 126/139 (90.6%), RDAP 112/139 (80.6%), and InternetDB 166/182 (91.2%).

Collection integrity and fusion-trainer verification now pass **41 tests** together; scorer tests pass **3**; Ruff and Python compilation pass. The post-collection [release-readiness report](model_readiness_20261018_postcollection.json) still has three blockers: no registered independent untouched holdout, no immutable evaluation bound to a passing policy run, and no validated final fusion bundle. The collection preflight is not a 10,000-record paired development cohort, and Tranco/feed labels cannot substitute for the plan’s independently supported release labels. No model was promoted and the runtime remains fail-closed.
