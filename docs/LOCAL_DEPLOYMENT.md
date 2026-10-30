# Local SCYTHE deployment

Run commands from the SCYTHE repository root. Docker Desktop must be running in
Linux-container mode. Python 3.11+ is sufficient for the startup/check command;
it uses only the standard library. The ignored root `.env` must contain the
existing local application, database, Redis and runner secrets. The command
does not create, replace or display secrets.

```powershell
python scripts/local_deploy.py up
```

This validates resolved Compose listeners, builds images, starts services, waits
for readiness, exports the public localhost certificate, and verifies HTTPS to
Nginx and its backend route with hostname and certificate validation enabled.
Backend startup applies database migrations through its existing entrypoint.
Use `--no-build` to reuse previously built images. Initial image builds and ClamAV
signature downloads require internet access and can take several minutes.

```powershell
python scripts/local_deploy.py check
```

The check fails if a required service is missing/unhealthy or any service other
than Nginx publishes a port. Nginx must bind a loopback address. The root `.env`
on this machine uses HTTP 8080 and HTTPS 8443; ports are read from the resolved
configuration. With no port settings Compose defaults to 80/443. The Chrome
extension origin must match the reported HTTPS origin.

Open `https://localhost:8443/dashboard/` for this machine. The checker reporting
`local_infrastructure_ready` confirms infrastructure and TLS only. Model quality,
real inference, extension actions and complete scan behavior have their own
acceptance checks. It must not be read as model release approval.

## Starting a qualified model release

When an immutable release bundle has passed its independent evaluation, start
the dedicated model worker using the externally pinned checksum-manifest hash:

```powershell
python scripts/local_deploy.py up --release-bundle "C:\path\to\qualified-release" --release-checksums-sha256 <trusted-manifest-sha256>
python scripts/local_deploy.py check --release-bundle "C:\path\to\qualified-release" --release-checksums-sha256 <trusted-manifest-sha256>
```

Replace both example values with real release values. The lightweight backend
release verifier checks the bundle, passing evaluation, policy, contracts and
binding hashes before Docker startup. Experimental candidates do not qualify.
The `models` profile and release variables are supplied only to subprocesses;
the helper never rewrites `.env`. With release arguments, readiness also requires
`celery_model_worker` to be healthy. A configured `MODEL_RELEASE_ENABLED=true`
without verified release arguments is rejected rather than starting the base
stack with no model consumer. Supply the same release arguments for subsequent
checks. Do not treat a running worker alone as evidence of an end-to-end verdict.

## Full workflow verification

After startup, run the existing browser, extension and email smoke commands from
the repository root. They require the project test dependencies (including
Playwright/Chromium), create local test records, and write reports:

```powershell
python scripts/frontend_workflow_smoke.py --origin https://localhost:8443 --url https://example.org/ --output .local/browser-smoke.json
node scripts/test_extension_auth.cjs
python scripts/test_extension_browser.py --origin https://localhost:8443 --extension chrome-extension
python scripts/email_workflow_smoke.py --base https://localhost:8443 --allow-local-self-signed --output .local/email-smoke.json
```

The email smoke option explicitly permits this local self-signed endpoint; the
infrastructure checker still verifies the certificate and hostname. Review the
saved final verdict and model version: smoke success with `UNKNOWN` verifies the
unavailable path and does not establish model-enabled workflow completion.

## Local browser trust

The local self-signed certificate includes `localhost`, `127.0.0.1` and `::1` as
subject alternative names. Its private key stays in the Docker volume
`scythe_nginx_local_certs`. The public certificate exported to `.local/server.crt`
is ignored by Git. Ordinary container restarts and recreations reuse this
certificate, preserving browser trust.

On Windows, optionally trust this specific certificate in your current user
certificate store after checking the printed SHA-256 fingerprint:

```powershell
python scripts/local_deploy.py certificate
Get-FileHash .local/server.crt -Algorithm SHA256
certutil -user -addstore Root .local/server.crt
```

The script never imports trust automatically. Restart Chrome/Edge after a manual
import. Do not disable browser certificate verification. To remove the local
trust later, locate the SCYTHE localhost certificate in `certmgr.msc` under
**Trusted Root Certification Authorities → Certificates**, verify its fingerprint,
and remove that certificate only. Firefox may use a separate certificate store.

Deleting the certificate volume generates a new key/certificate and requires
updating browser trust. Avoid `docker compose down -v`: that command also deletes
database and other persistent application volumes. For normal shutdown use:

```powershell
docker compose stop
```

If an existing local certificate expires, stop Nginx and replace only its local
certificate volume through Docker Desktop after removing the old browser trust.
Never remove the PostgreSQL, Redis, backup or scan volumes for certificate renewal.

## Local boundaries and diagnostics

- Local hosting still needs internet for live websites, threat providers and
  signature updates. Missing provider access remains explicitly unavailable.
- The default stack binds Nginx to `127.0.0.1`; backend, database and Redis remain
  internal. The production overlay has a separate public-bind default.
- `docker compose ps` and `docker compose logs --tail 100 nginx backend` help
  diagnose startup failures locally. Review logs before sharing them.
- The checker intentionally hides Docker command error output because resolved
  environment/configuration diagnostics can contain credentials.
- For model artifacts and evaluation status, use the model release readiness
  report and deployment readiness documentation. Infrastructure readiness does
  not resolve existing model-quality or runtime-image security findings.

Verification on 2026-10-16: local listener confirmed as `127.0.0.1:8443`; generated
SAN verified with OpenSSL; checker passed both HTTPS routes using the exported
certificate without bypassing TLS validation. The startup helper and existing
deployment/security regression tests passed together (46 tests).
