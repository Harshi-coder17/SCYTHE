# Local release operations verification â€” 20 October 2026

This is operational and experimental compatibility evidence. No model was qualified or activated.

## Backup ownership and authenticated recovery

The actual named local Docker volume `scythe_db_backups` had 14 entries owned by legacy UID/GID 1001. The only application consumer of that named volume is the normal Celery worker, running UID/GID 10001. Other services' anonymous backup volumes and unrelated projects were excluded. A read-only dry run verified the mount, rejected symlinks and special files, and hashed content and modes. A confined ownership migration changed those 14 entries to 10001:10001. Content and modes were unchanged; no legacy entries remained. The normal worker now has write access.

The current-source worker and beat images were built, then recreated after the collector completed its current batch and disabled its disposable account. Collection resumed against the same frozen run. Both services became healthy. Source hashes of `services/backup_crypto.py` and `tasks/db_backup.py` in the running worker match the working tree.

The normal worker subsequently created an AES-256-GCM authenticated backup using a read-only exported PostgreSQL snapshot. Verification authenticated before restore, restored only into a uniquely named disposable database, and matched all 13 table counts plus the schema digest. The disposable database was dropped. Existing backups were not pruned, and plaintext never reached the host. An earlier isolated worker test passed independently; its results are not substituted for the final real-worker result.

The initial failed test is retained: the old volume permissions denied backup creation before any restore database existed. This is corrected by the recorded migration, rather than hidden by the later successful test.

## Inference environment and testing

The clean virtual-environment image `sha256:5286895085740b1a172d7a7a8af3d57deb73a68967f51ad182f674e885e32338` verifies all declared inference dependency versions against both distribution metadata and actual imported modules. This corrects the earlier mixed sklearn/joblib metadata problem. Its PyTorch 2.8 runtime still has known advisories and is not characterized as security-cleared.

The experimental Docker verifier now accepts the exact finalized validation membership, instead of requiring eight images from the old v4 run. It rejects missing path scores, foreign captures, and duplicated capture identifiers. Five regression cases and Ruff passed. The backup, restore-verifier, and dependency-contract suites passed another 24 tests. These focused counts overlap portions of the wider host suite and must not be added to it indiscriminately.

Frozen model and dataset artifacts remain unchanged. `MODEL_RELEASE_ENABLED` is false in the actual normal worker. Qualified-model incident activation and rollback are not claimed by these infrastructure checks.

## Evidence

Read `../../audit-output/local-release-runtime-20261020/`: initial and successful backup reports, ownership dry-run/apply evidence, migration source, running-worker source parity, exact dependency contract, and isolated runtime candidate experiments. The experimental PyTorch 2.9 build is retained as a diagnostic; it does not resolve every subsequently discovered advisory. A later runtime candidate requires its own compatibility evidence before source dependency pins can change.

## v5 deployed-image development parity

All 36 quick/deep comparisons across the finalized 18 validation captures passed in the clean dependency image. There were zero failures across 36 warm scores per path. With a 2-CPU/4-GiB bound and the actual Windows bind-mounted encoder storage, quick p95 was 164.63 ms and deep p95 was 11,592.94 ms. Concurrent host load and filesystem caching were uncontrolled. These values describe this inspected development set; they do not constitute independent release quality or latency qualification. Cold stage measurements and per-input differences remain in `worker_report_v5.json`.

## Separate patched-runtime compatibility experiment

The official CPU wheels PyTorch 2.14.1 and torchvision 0.29.1 passed the exact import/metadata contract and all 38 v6 quick/deep prediction comparisons across 19 finalized validation captures. The maximum normalized-embedding difference was 2.35e-7; native fusion probability difference was zero. All 76 warm scores succeeded. These models were originally trained under the preserved historical 2.8 encoder lock. A new immutable compatibility overlay explicitly records the updated runtime without rewriting that training history.

**Storage differs from the v5 experiment:** v6 copied the exact checksum-verified checkpoint and pinned vendor source once into an isolated 512-MiB tmpfs. Root owned the copied files (0444) and directories (0555), then the bootstrap dropped to runtime UID/GID 10001 with no runtime write access. Encoder integrity was still rehashed on every use. The container had no network and was limited to 2 CPUs and 4 GiB. Quick p95 145.56 ms and deep p95 3,418.28 ms describe this RAM-backed experiment; they do not certify Windows bind-mounted deployment latency. The v5 11,592.94-ms deep p95 above used the actual Windows bind mount.

The checksummed compatibility and storage-proof directories are `../../lightgbm_dataset/prospective_reviewed_dev_v6_runtime2141_compatibility_v1/` and `../../lightgbm_dataset/prospective_reviewed_dev_v6_runtime2141_storage_proof_v1/`. The latter binds the completed report SHA256, original/copied checkpoint digests, bootstrap source, resource bounds, and explicit storage limitation without modifying the already completed report. A first attempt failed before inference with ENOMEM during immutable cohort reads under concurrent image-build/diagnostic load; that failure is preserved separately.

Source inference pins now select the verified 2.14.1/0.29.1 runtime. Exact OSV queries returned eight known entries for the 2.8.0+cpu positive control and zero for 2.14.1 and 2.14.1+cpu at the saved query time. This is not a claim that all OS/image findings are cleared. The clean source image still requires its completed build and deployment checks. The local shadow flag was changed to false without modifying credential bytes; existing API/normal-worker environments retain their previous value until a later controlled restart. Production model release remains disabled.

## Qualified model-worker warm-up

Cold imports/artifact/encoder loads can exceed the ordinary 55-second soft / 60-second hard inference budget. The separate `tasks.warm_model_release` task uses the same `models` queue and actual single prefork inference child, with 180-second soft / 240-second hard limits. It requires the configured checksum-verified qualified release. It warms component and native-model kernels with a generated gray software-test image and a reserved `.invalid` lexical URL; it makes no target network requests, creates no scans or incidents, and returns no probabilities or verdicts. Temporary image files are removed. Disabled, corrupt, unavailable, or failed bundles return unavailable; no candidate is promoted by warming.

After a qualified bundle exists, start only the model worker with its verified release configuration while public/API scoring is still disabled. Run `docker exec scythe_celery_model_worker python -m tasks.model_inference` and require exit zero plus `status=warmed`, the expected model/hash, both supported paths, and the recorded child PID before enabling API scoring/accepting scan traffic. The command queues the task and waits up to 250 seconds; it does not warm a short-lived CLI process. Repeat after every model-worker restart, child replacement, bundle/runtime change, or rollback. Keep the single `models` worker/concurrency-one configuration; warming a different process does not establish readiness. A hard-killed warm task can replace the child, so recheck worker health and repeat instead of accepting traffic. The normal scan limit remains 55/60 seconds.

No qualified bundle currently exists, so successful qualified warm-up and model-driven deployment are not claimed. Unit success cases use explicit software fixtures only.

## Patched shadow worker deployed and verified (20 October, 07:08 UTC)

The running `scythe_celery_shadow_worker` now uses the proper source-built image `sha256:85ccaf181c8bc698adeccbe1765d9c6c863e586c32d1154f1aa84ff4fa1521c4`. Its warm-up implementation, dependency verifier and shadow requirement files match the current source byte-for-byte; a further rebuild was unnecessary. Only this container was recreated. Before/after container IDs verify that the API, normal worker, beat, sandbox and every other running service stayed unchanged.

The exact worker responded to a destination-specific Celery ping, and Docker health is healthy. In the actual running worker, imported versions and distribution metadata match every declared inference pin, including PyTorch `2.14.1+cpu` and torchvision `0.29.1+cpu`. Both model-release and shadow-scoring flags are false. The disabled warm task returned unavailable without loading a bundle. A direct disabled shadow task using an isolated temporary directory returned null probabilities and `automatic_incident_signal=false`; its temporary diagnostic file was removed. No scan, incident, database row, or existing scan artifact was created by this proof.

The image override used for this controlled replacement is retained in `../../audit-output/local-release-runtime-20261020/shadow_patched_local_override.yml`. Existing API/normal-worker environments remain unchanged; they may still dispatch shadow diagnostics, which the now-disabled shadow worker safely reports unavailable. Apply their shadow flag only at a later controlled restart. No qualified model exists or was activated.

Fourteen focused warm-up, dependency-contract and placeholder tests passed. The current-source Bandit SAST High/Medium gate passed again after the warm-up implementation; reports are in `../../audit-output/security-shadow-deployed-20261020/`. Initial host test commands failed because they selected an incomplete virtual environment or omitted the retained dependency path; rerunning with the established host dependencies and explicit backend/dataset paths passed. These environment failures do not represent application test failures.

The checksummed deployment proof is `../../audit-output/local-release-runtime-20261020/shadow_patched_deployment_verified.json`. Its scope is exact declared Python dependency/import parity and disabled operational behavior. It does not clear all transitive or operating-system advisories; the existing sandbox OS vulnerability disposition remains open and separate.
