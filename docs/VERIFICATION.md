# Verification and CI

The committed `.github/workflows/verify.yml` runs independent backend, sandbox, quality and source-security jobs on pushes and pull requests. It has read-only repository permissions and SHA-pinned official actions. A separate manually selected heavy job builds a disposable Compose stack, exercises actual browser URL/file reports and extension session exchange, and runs a mandatory pinned Trivy image scan. A skipped heavy job is not evidence that browser workflows or image CVEs passed.

## Fast local checks

Use the pinned Linux runtime environment for backend tests; native host environments must first install the backend lockfile and required OS libraries. No dataset archives, private credentials, IMAP mailbox, Windows `_deps`, external model files or screenshots are required for these tests.

```powershell
# Run from SCYTHE, with backend dependencies installed.
$env:PYTHONPATH = (Resolve-Path containers/backend).Path
python -m pytest --import-mode=importlib containers/backend/tests containers/backend/services/email/tests -q
python -m pytest scripts/tests -q
python -m pytest -c containers/sandbox/pytest.ini containers/sandbox/tests -m "not integration" -q
node scripts/test_extension_auth.cjs
python scripts/lint_changed.py
```

The URL-feature regression fixture under backend tests records 17 independent training outputs and the original training source SHA256. It checks exact canonical URLs, class-independent feature values and all 15 columns, including Unicode, IPv4/IPv6, nonstandard ports, shortening, subdomain boundaries and null bogon state. It avoids importing out-of-repository training scripts or platform-specific binary dependency folders. Update this fixture only as a deliberate feature-contract version change with independent training provenance.

`lint_changed.py --base <commit>` verifies its baseline as a Git commit, passes paths without shell interpolation and lints complete changed Python files. It also includes untracked, nonignored source in local mode. The CI quality job validates workflow syntax/expressions using checksum-verified actionlint, then runs extension JavaScript syntax and auth/UNKNOWN/stale-document regressions.

## Production overlay and security tooling

```powershell
python scripts/check_production_config.py --env-file .env.production --output production-config-check.json
python scripts/security_scan.py --checks secrets sast deps --output security-results
python scripts/security_scan.py --checks images --trivy-image aquasec/trivy@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222 --output security-results-images
```

The production checker merges every Compose profile with the production overlay without resolving service environment files or printing merged configuration. The explicit environment file supplies interpolation values; inherited deployment variables are removed from that subprocess to prevent an unnoticed override. It checks production/TLS enforcement on API/workers, explicit public host/HTTPS origins, backup-key presence/strength, immutable sandbox image pinning, nginx's read-only certificate bind, writable runtime tmpfs and absence of a certificate tmpfs shadow mount. It never starts containers. This static check does not validate certificate identity/CA, DNS ownership, secret escrow, restore success or production model quality.

Security checks fail if a requested scanner, target, lockfile or image is missing; a missing check cannot report clean. Source scanning snapshots tracked plus untracked nonignored files, avoids following links outside the repository and does not copy ignored `.env` files. Any accidentally committed secrets remain scan targets. Gitleaks output is fully redacted; configuration/env dumps must never be uploaded as CI artifacts.

CI verifies Gitleaks 8.30.1 and actionlint 1.7.12 release archives against pinned SHA256 values. Dependency scans use the complete hashed backend/runner/sandbox lockfiles. Container scans fail on HIGH/CRITICAL findings without silently treating absent images as clean. Review actual reports rather than assuming the existence of CI makes a release safe.

## Heavy workflow

In GitHub Actions, choose **Verify SCYTHE**, select **Run workflow**, and enable `run_compose_smoke`. Use a hosted disposable runner; this workflow creates and removes its own stack/volumes and never belongs against an existing personal checkout's active containers. Credentials are generated locally, never printed and removed with the ephemeral environment. Real mail ingestion, paid APIs and production notifications are not enabled. The final risk-fusion placeholder remains required by the smoke test.

The local equivalents, after an already authorized development stack is running, are:

```powershell
python scripts/frontend_workflow_smoke.py --origin https://localhost:8443 --url https://example.org/ --output frontend-workflow-smoke.json
python scripts/test_extension_browser.py --origin https://localhost:8443 --extension chrome-extension
```

These scripts require a real Playwright Chromium installation; the sandbox image already contains Chromium. The browser smoke creates disposable test accounts, benign URL/file scans and ownership/revocation checks; its report lists accounts for cleanup. A self-signed development TLS certificate is accepted only inside this development fixture. Production TLS remains mandatory under the overlay.

GitHub-hosted execution is not claimed until the workflow has actually run after publication. Latest local verification: 154 backend and offline-email tests, 45 script-gate tests, 10 sandbox tests, extension auth checks, and Ruff over 83 changed Python files passed. The updated workflow passed actionlint 1.7.12. After rebuilding and rolling out the changed backend/worker/beat/runner images, the browser URL/file/history/ownership/logout workflow passed all eight checks; both disposable accounts were disabled afterward. The real unpacked-extension bridge passed. The email workflow passed 22 checks, including attachment integrity, ClamAV, ownership, idempotency, and the `UNKNOWN` placeholder gate. Encrypted snapshot restore passed on PostgreSQL 16.15 with matching schema and row counts; the disposable restore database was dropped and prior backups were untouched. Static production Compose validation passed using temporary fixture values. Gitleaks, Bandit, and pip-audit passed across the source tree and lockfiles. The full evidence and image scan reports are retained in the sibling `audit-output/parallel-stage` directory.

The image security gate is still failing: the latest scan reports backend 44 high; worker/beat 75 high and 1 critical each; shadow worker 54 high; runner 44 high; browser sandbox 67 high and 1 critical; and PostgreSQL `gosu` 24 high and 1 critical generic Go findings. Nginx, Redis, socket proxy, ClamAV, and Alpine network-helper report zero high/critical findings. Keep the gate failing; review the image reports and [gosu's upstream applicability guidance](https://github.com/tianon/gosu/blob/1.19/SECURITY.md) before any evidence-based exception.


## Encrypted backup restore verification

After deploying a worker whose PostgreSQL tools match the database server major version, run:

```powershell
python scripts/verify_backup_restore.py --output backup-restore-verification.json
```

This invokes the existing backup task in a fresh private verification subdirectory, leaving existing archives and their retention untouched. A read-only exported database snapshot binds source table counts and the dump consistently. Dump, worker restore and server archive-reader major versions must match before backup. The helper creates a unique disposable database owned by the application role, decrypts only inside the worker with the key on OpenSSL stdin, streams directly to pg_restore over the internal database connection, and verifies exact snapshot row counts plus column/constraint/index schema hashes. It uses no host plaintext archive or key argument and always attempts to drop only the database it successfully created. The encrypted verification archive and aggregate manifest remain private in the backup volume as evidence; failed cleanup reports the exact disposable database identity requiring attention. No live application database is restored into or removed.


## Runtime image maintenance

Runtime images pin Python and upstream image digests, apply available distro updates, and include OpenMP (`libgomp1`) wherever the installed LightGBM library is exercised. The worker carries PostgreSQL 16 dump/restore tools matching the database service. After installing the pinned Python tooling, the runtime removes pip: its bundled installer-only dependencies are unnecessary in deployed services. The application dependencies and current setuptools remain installed. Tests that bootstrap a package manager do so only inside disposable test containers, never the running services.

An image gate failure remains a failure when a distro vendor has not published a fix. Source/lockfile scan success does not imply an OS image is clean. Preserve the dated image reports and reassess when vendor fixes become available. Existing archives made by a newer PostgreSQL client can require that newer archive reader; retain them and their recovery tooling rather than deleting them during this change.
