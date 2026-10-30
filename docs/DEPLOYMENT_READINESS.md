# SCYTHE deployment readiness

**Local infrastructure is verified; complete model-enabled deployment is not yet ready.** The Compose stack runs on this machine with a persistent localhost certificate. Trained experimental components can score in the isolated shadow worker, but a validated final fusion release does not exist. The model and remaining image-security limitations below must stay visible.

## Current status — 22 October 2026 IST

V20 is the latest completed, runtime-parity-verified experiment: 947 development
captures (866 proxy benign, 81 feed-supported phishing), with all 378
validation/path predictions matching the worker image. Warm diagnostic p95 was
36.72 ms quick and 1,205.87 ms deep, with zero failures across 50 scores per path.
These isolated tmpfs measurements exclude queueing, capture, providers and full
scan latency. Validation PR-AUC was 0.715 quick and 0.915 deep; these are small,
already-inspected development results, not independent release evidence.

There is no eligible deployment threshold. With only 173 benign validation
records, even zero false positives has a Wilson upper bound of 2.17%, above the
approved 1% gate. See
`../../audit-output/model_runtime_v20_20261022_v1/worker_report_v20.json`.

The corrected v21 selection preview restores omitted frozen source runs and
contains 958 records (866 benign, 92 phishing). It has not been trained. Its
prepared binding accounts for 959 historical captures: 958 retained and one
newer valid replacement. The binding requires historical image identities and
blocks training until 10,000 usable development records, including 4,000 per
class, exist. Evidence is in
`../../audit-output/cohort_continuity_20261022_v1/`.

The 22 October local infrastructure check passed. Collection and training are
running concurrently. Independent release labels remain zero; restricted dataset
approval, independent holdout evidence, path-specific qualification and qualified
model activation remain outstanding. Existing OS security findings remain open.

Recovery screening verified 120 omitted saved phishing captures: 65 have all
expected evidence references and 55 lack paired scan evidence. These are not
automatically eligible. The checksummed inventory is
`../../audit-output/phishing_recovery_20261022_v1/report.json`.

The dated sections below retain earlier verification results; their references
to a version as "latest" or "current" apply only to that historical checkpoint.

## Historical verification — 21 October 2026 IST

### Current local dependency revision

Active Python locks and the local API, worker, beat, inference, research and
browser sandbox images now use Pillow 13.0.0 and certifi 2026.10.19. SAST and
all four dependency audits pass. The live HTTPS quick workflow, authentication
revocation, unavailable-result handling and absence of fixture incidents passed
after rollout. The only local `.env` change was the non-secret sandbox image
pin; credentials were preserved.

The current image-preserving start command, from this repository directory, is:

```powershell
docker compose --profile shadow -f docker-compose.yml -f ../audit-output/security_runtime_patch_20261021_v1/image_override.json up -d --no-build --pull never
python scripts/local_deploy.py check
```

The shadow worker can remain running for diagnostics while both shadow dispatch
and model release activation stay disabled. The override retains the patched
local images; older dated overrides restore older dependencies. Rollback image
IDs and the previous non-secret sandbox pin are recorded beside the override.
Fresh image scans still report backend 44 High, inference 49 High, and sandbox
63 High/one Critical OS findings without listed fixed versions. Release remains
blocked; Python dependency clearance does not clear these OS advisories.

V12 is the latest experiment, trained on 240 eligible development captures
(192 training: 131 benign + 61 phish, 48 validation: 33 benign + 15 phish),
integrating two new prospective collection runs on top of v11. All 96
validation/path predictions (48 quick + 48 deep) matched the patched
deployment image (sha256:76cc2c7a5e5e...) with zero delta. Diagnostic
warm p95 was 38.32 ms quick (p50 29.16 ms) and 801.65 ms deep (p50 704.78 ms),
with zero failures in 50 scores per path. The encoder used bounded tmpfs,
so these are diagnostic timings, not production Windows-storage qualifications.

Validation PR-AUC was 0.99583 quick and 1.00000 deep (ROC-AUC: 0.99899 quick,
1.00000 deep). Both deployment thresholds remain constrained: zero false positives
among 33 benign validation samples yields a 10.43% Wilson 95% upper bound
(exceeding the 1.0% maximum gate). No independent release holdout was evaluated,
and runtime scoring remains strictly fail-closed at UNKNOWN. Evidence is in
../../audit-output/model_runtime_v12_20261021_v1/worker_report_v12.json and
../../lightgbm_dataset/prospective_reviewed_dev_v12_fusion_v2/.

V11, v10, and v9 remain frozen historical milestones. Overall collection pool
stands at 40 runs, 1,850 attempts, and 798 observed captures (518 benign, 280 phish).

The current completed experiment is `prospective_reviewed_dev_v9_fusion_v2`, trained
on 180 paired development captures (144 training, 36 validation). All 72
validation/path predictions matched the actual deployment image. Diagnostic warm
p95 was 78.45 ms for quick scoring and 1,909.11 ms for deep scoring; these are
isolated RAM-backed-worker measurements, not a complete operational latency
qualification. Both deployment thresholds remain infeasible: zero false positives
among 23 benign validation samples still gives a 14.31% Wilson upper bound.

Nine actual user review decisions were imported without rewriting them: eight
uncertain and one disagreement. Independent supporting evidence remains
unvalidated, so no release labels were created. The disputed training sample is
quarantined for future cohorts; frozen v9 remains unchanged. No independently
supported 2,000-phishing/5,000-benign release holdout has been evaluated.

Controlled service recreation, TLS, quick UNKNOWN, deep/file evidence and history,
isolation, paced logout/revocation, and encrypted disposable restore passed.
Release and shadow scoring are disabled consistently across API, worker, shadow
worker and beat. Credentials, exact deployed images and scheduler storage were
preserved. Open image advisories and qualified model activation remain blockers.

The checksummed [current stage report](../../audit-output/local_release_progress_20261021_v2/REPORT.md)
records model versions, actual measurements and limitations. The next validated
development preview will expand beyond 194 eligible records as new collection
runs complete; frozen v11 uses 194.
Use the dependency-patch startup override above to retain the current images.
The earlier operations reports preserve recovery evidence but their older image
overrides do not retain today's dependency fixes. Earlier dated experiments
below are historical evidence, not the current cohort or qualification status.

## Local deployment

The local stack uses the root `.env` and a self-signed certificate generated inside Nginx and retained in its dedicated local certificate volume. A public domain is not required. Start or rebuild it from the repository root with:

```powershell
python scripts/local_deploy.py up
python scripts/local_deploy.py check
```

Open `https://localhost:8443/dashboard/` using this machine's configured ports. HTTP `8080` redirects to HTTPS. Both listeners bind loopback by default. The checker exports the public certificate and verifies TLS hostname/expiry against it; [local deployment instructions](LOCAL_DEPLOYMENT.md) explain optional browser trust without disabling verification. API and worker health are also visible in `docker compose ps`. Infrastructure readiness and model release readiness are separate checks. The experimental shadow worker is an optional profile and stays off by default.

Local verification on 2026-10-16 passed the full URL/file browser workflow, UI regression suite, extension authentication checks, and the real unpacked Chrome extension bridge. The full-flow test accounts were disabled after the run. Evidence is in the sibling `../../audit-output/local-deployment-smoke-20261016.json` and `../../audit-output/local-ui-fixture-20261016.json`.

## Model status

The 2026-10-16 implementation adds a separate `models` CPU queue, native model and
safe JSON visual-head loading, checksum-bound release contracts, explicit missing
evidence, model-aware quickscan caching, deduplicated incidents, and persistence
before terminal WebSocket updates. The approved local quality policy is recorded
in `local_operational_model_policy_v1.json`: recall at least 80%, benign false
positives at most 1%, with confidence-bound acceptance and target-worker latency.
See `local_model_release.md` for prospective registration, scoring, evaluation,
and immutable packaging. `scripts/local_deploy.py` refuses to activate an
unverified release and never rewrites the local `.env`.

The paired-data trainer is in the sibling
`lightgbm_dataset/prospective_fusion.py`. It verifies capture/label/raw-enrichment
evidence and domain/campaign exclusions, then fits component heads out of fold
before training fusion. A registered prospective paired development manifest now
contains 20 rows; `scythe_fusion_v1` has been trained on 14 and validated on 6.
Its PR-AUC/ROC-AUC are 0.50, with 3/3 benign validation false positives, no scan
evidence in any row, and no known campaign groups. It is a pipeline baseline, not
a usable model. No independently supported untouched release cohort exists.
Historical datasets remain useful for their documented component experiments;
unrelated rows cannot supply missing paired evidence or decision-time enrichment.

Model training is complete for **experimental candidates**, not for a model approved to drive SCYTHE verdicts. MobileCLIP v1/v2 and the newer v3 visual head have versioned, checksum-bound artifacts and evaluation reports. V2 scored PR-AUC 0.943 and ROC-AUC 0.961 on the existing 1,991-image test split, but had about 1,540 false positives per 10,000 benign images at its validation-selected threshold. V3 reduced weighted false positives on the previously inspected external screenshot comparison from 703 to 567 per 10,000, while recall fell from 25.6% to 23.1%; the paired domain-bootstrap interval favors lower FPR but both rates remain outside policy. This comparison is development evidence, not an untouched release evaluation. See [the dated training status](MODEL_TRAINING_STATUS_20261017.md) for current URL, visual, and fusion results.

The latest URL-only experimental candidate, `lightgbm_prospective_url_v2`, has
validation PR-AUC 0.9799 on 21,997 rows. A separate PhreshPhish same-corpus
temporal test reached 44.2% recall and 97 false positives per 10,000 negatives
at its frozen threshold; previously inspected cross-source results still show
poor transfer. Tranco controls are proxies and feed labels are not independent
adjudications. These URL models do not contain all nine decision-time enrichment
features and do not replace the v10 fusion model.

The first prospective pilot produced 16 observed captures across 32 attempts.
The later curated paired cohort contains 20 eligible records from 37 observations
across 88 attempts (11 Tranco proxy-benign, 9 feed-supported phishing). The
2026-10-17 follow-up run contains 8 candidate rows but only 4 successful capture
statuses; 3 successful records overlap the existing validation manifest, leaving
1 novel successful capture. These labels and captures do not establish deployment
quality. The separate source-acquisition inventory preserves newly downloaded
paired data and its licensing/timestamp limitations without silently assigning
it to training or release evaluation.

The runtime release loader is implemented and fails closed while no validated
bundle is configured: ordinary model verdicts remain `UNKNOWN`. A passing
release can use the separate `models` worker; experimental components run only
through the diagnostic shadow path. Shadow scoring is enabled in the current
local Compose environment, but its outputs do not change risk, severity, alerts,
or incidents. The owner-approved operational policy is already recorded. The
current report is `../../audit-output/model-release-readiness-20261018.json`;
with that policy supplied, it reports three remaining gates: a qualified
untouched holdout, an immutable quality/coverage/latency evaluation, and a
validated final fusion bundle. Earlier readiness reports remain historical.

## Verified in the local stack

- The complete backend and offline-email test suite passed 154 tests; the deployment/security script suite passed 45 tests; sandbox safety tests passed 10 tests. Extension authentication checks and Ruff over 83 changed Python files passed.
- The live browser workflow passed URL capture, two stable terminal status observations, file scanning, session history, tenant isolation, logout revocation, and back-navigation checks. The unpacked extension authentication bridge passed.
- The live email workflow passed 22 checks across the API, four Celery branches, ClamAV, report persistence, attachment integrity, ownership, and duplicate handling. Its result remained `UNKNOWN` with no incident. Mailbox ingestion correctly stayed unavailable because no mailbox owner or address is configured.
- An encrypted backup restored into a disposable database using PostgreSQL 16.15 tools. Table counts and schema hashes matched; cleanup succeeded and existing backups were not pruned.
- The post-hardening local rollout passed the live browser URL/file/history/ownership/logout workflow with all eight checks passing; the two disposable test accounts were disabled afterward. Backend, worker, beat, and sandbox-runner containers report healthy. The backend probe uses its real `/` health route; the runner probe uses `/health`.
- Screenshot intake now fully decodes and rewrites uploads as metadata-free PNGs before storage, so OCR never receives the original TIFF container. Regression tests confirm TIFF-to-PNG conversion and metadata removal.
- The production Compose overlay passed static validation with temporary fixture values. This did not validate a real certificate, DNS, or external secret storage.
- Full source security checks passed: Gitleaks, Bandit, and pip-audit for all three lockfiles. The production example template is explicitly allowlisted as placeholders only.

## Remaining for complete local model deployment

1. Expand the paired development corpus and provider/scan-signal coverage; balance
   sources across both classes, review capture quality, and train a new v10 fusion
   candidate with grouped out-of-fold component predictions. Preserve fusion v1
   as the small, chance-level baseline.
2. Register a new untouched independently labelled cohort, freeze model and
   threshold choices, and pass the accepted recall/FPR confidence-bound,
   coverage, and target-worker latency gates. Existing inspected cohorts remain
   development evidence.
3. Package and verify that passing release, configure its local checksum trust
   anchor, and exercise real model verdicts, extension actions, incidents, and
   failure recovery in the full local browser/file/email workflow. Current
   infrastructure tests do not supply missing model-quality evidence.
4. Retain unresolved image-security findings and complete individually supported
   fixes or mitigations; healthy services alone do not resolve them.

Public DNS, production domains/certificates, a cloud secret manager, hosted CI,
and a personal mailbox are outside the requested local deployment scope. Local
`.eml` workflow testing does not require mailbox credentials.

## Optional public production handoff

1. **Resolve the image scan gate.** The latest pinned Trivy 0.76 scan reports unresolved high/critical findings in the Debian runtime images: backend 44 high; worker and beat 75 high plus 1 critical each; shadow worker 54 high; runner 44 high; browser sandbox 67 high plus 1 critical. The pinned PostgreSQL image has 24 high and 1 critical generic Go standard-library findings in upstream `gosu`; `govulncheck` v1.1.4 found zero reachable vulnerabilities in the extracted binary, but the raw Trivy report remains preserved. Nginx, Redis, socket proxy, ClamAV, and the Alpine network helper have zero high/critical findings. Removing unused curl CLIs lowered backend/runner from 48 to 44 high and worker/beat from 77 to 75 high without dropping health probes. The Bookworm candidate had more findings and was rejected. Exact reports: `../../audit-output/parallel-stage/deployment-image-security-verified-final/`, Bookworm comparison `../../audit-output/parallel-stage/python-bookworm-candidate/`, and `gosu` review `../../audit-output/parallel-stage/image-findings-investigation.md`. Keep the gate failing until findings are fixed or individually assessed with evidence.
2. **Supply real production identity and secrets.** Configure `SCYTHE_PUBLIC_HOST`, its HTTPS `SCYTHE_PUBLIC_ORIGIN`, DNS, and a trusted certificate under `containers/nginx/certs`. Generate production application/database/Redis/runner secrets; store them in the production secret manager. Escrow `BACKUP_ENCRYPTION_KEY` separately from the backup volume and document a recovery procedure. The local `.env` is for this development stack, not production deployment.
3. **Supply passing model evidence.** Operational model limits are already accepted in `local_operational_model_policy_v1.json`. A newly registered independent release evaluation and validated fusion bundle remain technical requirements. Previously examined datasets cannot establish generalization. A phishing model must not be treated as an arbitrary-file malware classifier.
4. **Keep mailbox polling disabled until configured.** If required, configure the dedicated mailbox owner, address, scoped poller token, and IMAP credentials, then test against an approved mailbox. No mailbox was contacted in these checks.
5. **Run hosted CI after publishing the branch.** Local checks do not prove that GitHub Actions ran. The heavy Compose/browser job also fails its current image gate while the findings above remain.

### Production configuration handoff

Start from the tracked, secret-free [`.env.production.example`](../.env.production.example) template. Copy it to `.env.production`, set the real public host and HTTPS origin, and generate each secret independently with `python -c "import secrets; print(secrets.token_hex(32))"` into the approved secret manager. Materialize the values only in the deployment environment; do not commit or attach the populated file. Give the checker an explicit file path:

```powershell
python scripts/check_production_config.py --env-file .env.production
```

The checker rejects missing/short or reused database, Redis, runner, and backup secrets; reserved/example hostnames; malformed or mismatched HTTPS CORS origins; and enabled or unset experimental shadow scoring. It still performs static Compose validation only. Before starting the stack, place the CA-trusted `server.crt` and matching `server.key` in `containers/nginx/certs`, verify DNS and certificate hostname/expiry from the production host, and validate the real deployment through the approved change process. The repository cannot supply or attest those environment-specific values.

The deployment gate and static configuration checker are documented in [VERIFICATION.md](VERIFICATION.md). The official `gosu` maintainers describe how to assess whether generic Go CVE reports apply to their binary in [their security guidance](https://github.com/tianon/gosu/blob/1.19/SECURITY.md); this does not make the Trivy findings disappear or replace an explicit review.
