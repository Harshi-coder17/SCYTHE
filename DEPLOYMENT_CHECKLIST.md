# SCYTHE Deployment Checklist

> **Track D — End-to-End Workflow Verification**  
> Updated: 2026-10-31 | Verified against: local dev stack (13 containers)  
> Model: `candidate_fusion_v26` | Feature contract: `scythe_fusion_v2`

---

## 1. Prerequisites

### System Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| Docker Engine | ≥ 24.x | Compose v2 plugin required (`docker compose`) |
| Docker Compose | ≥ 2.20 | `docker-compose` (v1) is **not** supported |
| Python | 3.11 | Used for scripts, smoke tests, and `.venv` |
| Available RAM | 6 GB | 13 containers, model worker ~1–2 GB |
| Available Disk | 10 GB | Postgres data, Redis AOF, scan artifacts |
| OS | Linux / macOS / Windows (WSL2 or native Docker) | |

### Required `.env` Variables

Copy `.env.production.example` → `.env` (dev) or `.env.production` (prod) and populate **all** of these:

#### Mandatory Secrets (never commit)

| Variable | How to Generate | Purpose |
|---|---|---|
| `SECRET_KEY` | `python -c "import secrets; print(secrets.token_hex(32))"` | JWT signing key |
| `SCYTHE_DB_PASSWORD` | `python -c "import secrets; print(secrets.token_hex(32))"` | Postgres scythe user |
| `POSTGRES_ROOT_PASSWORD` | `python -c "import secrets; print(secrets.token_hex(32))"` | Postgres superuser |
| `REDIS_PASSWORD` | `python -c "import secrets; print(secrets.token_hex(32))"` | Broker + cache Redis |
| `REDIS_SECURITY_PASSWORD` | Same as `REDIS_PASSWORD` or distinct | JWT-revocation Redis |
| `SANDBOX_RUNNER_SECRET` | `python -c "import secrets; print(secrets.token_hex(32))"` | HMAC auth for sandbox runner |
| `BACKUP_ENCRYPTION_KEY` | `python -c "import secrets; print(secrets.token_hex(32))"` | Backup AES key |
| `EMAIL_POLLER_TOKEN` | `python -c "import secrets; print(secrets.token_hex(32))"` | Email pipeline auth |

#### Required Configuration

| Variable | Example Value | Purpose |
|---|---|---|
| `ENVIRONMENT` | `development` / `production` | Controls debug routes, structured logging |
| `DEBUG` | `false` | Set `true` only in dev; disables FastAPI docs in prod |
| `CORS_ALLOWED_ORIGINS` | `https://yourdomain.com,chrome-extension://<ext-id>` | Browser origins allowed; must include extension origin |
| `ALLOWED_HOSTS` | `yourdomain.com,localhost` | TrustedHostMiddleware list |
| `NGINX_HTTPS_PORT` | `8443` (dev) / `443` (prod) | HTTPS port |
| `NGINX_HTTP_PORT` | `8080` (dev) / `80` (prod) | HTTP port |
| `SANDBOX_IMAGE` | `sha256:<digest>` | Pinned sandbox container digest |
| `CLAMAV_FAIL_CLOSED` | `true` | **Must be `true`** — rejects files if ClamAV is unavailable |

#### Optional / Feature-Flag Variables

| Variable | Default | Notes |
|---|---|---|
| `SHADOW_SCORING_ENABLED` | `false` | Enables shadow worker for A/B scoring; experimental |
| `MODEL_RELEASE_ENABLED` | `true` (dev) | Enables the v26 model bundle; see §9 for caveats |
| `MODEL_RELEASE_CHECKSUMS_SHA256` | *(set to bundle hash)* | Required for checksum-verified model loading |
| `MODEL_RELEASE_HOST_DIR` | `./models/releases` | Host path mounted into model worker |
| `COMPOSE_PROFILES` | `shadow,models` | Activates optional service profiles |
| `REQUIRE_REAL_CERT` | `false` (dev) / `true` (prod) | Forces real TLS cert; self-signed rejected in prod |
| `VIRUSTOTAL_API_KEY` | *(optional)* | Threat intel enrichment |
| `GOOGLE_SAFE_BROWSING_API_KEY` | *(optional)* | Threat intel enrichment |
| `IPQUALITYSCORE_API_KEY` | *(optional)* | Threat intel enrichment |
| `SLACK_WEBHOOK_URL` | *(optional)* | Alert notifications |

---

## 2. Container Startup Sequence

SCYTHE uses Docker Compose dependency ordering (`depends_on: condition: service_healthy`). The correct logical startup order is:

```
1. postgres          → primary datastore; all backend services depend on it
2. redis             → broker + result cache; all Celery services depend on it
3. redis_security    → JWT-revocation store; backend depends on it
4. clamav            → AV scanning; backend depends on it (fail-closed)
5. docker_socket_proxy → scoped Docker API gateway for sandbox
6. sandbox_net_holder → network placeholder for sandbox isolation
7. backend           → FastAPI/Uvicorn; nginx depends on it
8. nginx             → TLS terminator + reverse proxy
9. celery_worker     → main async task runner
10. celery_beat      → periodic scheduler (file cleanup, health sweeps)
11. celery_model_worker → ML scoring worker (profile: models)
12. celery_shadow_worker → shadow scoring worker (profile: shadow)
13. sandbox_runner   → Playwright detonation container
```

### Startup Commands

```powershell
# Development (self-signed cert, all profiles)
cd "C:\Users\armaa\Desktop\Project details\SCYTHE"
docker compose --profile shadow --profile models up --build -d

# Check all containers are healthy
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Health Check Commands

```powershell
# Wait for all core services to be healthy
docker compose ps

# Individual container health
docker inspect --format '{{.Name}} {{.State.Health.Status}}' \
  scythe_postgres scythe_redis scythe_redis_security \
  scythe_clamav scythe_backend scythe_nginx

# Backend API health
$r = Invoke-WebRequest -Uri "https://localhost:8443/" -SkipCertificateCheck -UseBasicParsing
$r.StatusCode   # Expected: 200
$r.Content      # Expected: {"service":"SCYTHE Backend",...}
```

### Expected Healthy Container List (all running)

```
scythe_postgres          Up (healthy)
scythe_redis             Up (healthy)
scythe_redis_security    Up (healthy)
scythe_clamav            Up (healthy)
scythe_socket_proxy      Up
scythe_sandbox_net_holder Up
scythe_backend           Up (healthy)
scythe_nginx             Up (healthy)
scythe_celery_worker     Up (healthy)
scythe_celery_beat       Up (healthy)
scythe_celery_model_worker  Up (healthy)   ← requires --profile models
scythe_celery_shadow_worker Up (healthy)   ← requires --profile shadow
scythe_sandbox_runner    Up (healthy)
```

---

## 3. Chrome Extension Loading

### Extension Manifest Location

```
C:\Users\armaa\Desktop\Project details\SCYTHE\chrome-extension\
```

**Manifest path:** `chrome-extension\manifest.json`

### Key Manifest Fields (v1.0.0)

| Field | Value |
|---|---|
| `manifest_version` | 3 (MV3) |
| `name` | SCYTHE Threat Shield |
| `version` | 1.0.0 |
| `background.service_worker` | `background.js` |
| `permissions` | `tabs`, `activeTab`, `storage`, `scripting`, `webNavigation` |
| `host_permissions` | `http://*/*`, `https://*/*` |
| Content scripts (document_start) | `config.js`, `auth-bridge.js` |
| Content scripts (document_idle) | `content.js`, `bdr.js` |

### Step-by-Step: Load Unpacked Extension in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle, top-right)
3. Click **Load unpacked**
4. Navigate to and select: `C:\Users\armaa\Desktop\Project details\SCYTHE\chrome-extension\`
5. The extension "SCYTHE Threat Shield" appears with its icon
6. Note the **Extension ID** displayed under the extension name
7. Add `chrome-extension://<YOUR_EXTENSION_ID>` to `CORS_ALLOWED_ORIGINS` in `.env`
8. Restart the backend container for CORS changes to take effect:
   ```powershell
   docker restart scythe_backend
   ```
9. Click the SCYTHE icon in the Chrome toolbar to verify the popup loads
10. Log in with your SCYTHE account credentials

> **Note:** The extension does **not** synchronously block navigation. It submits URLs for async analysis after page load.

---

## 4. Smoke Tests

> All tests require a valid JWT. Obtain one via the login endpoint first.

### 4.1 — Authentication

```powershell
# Register a test account (202 = accepted)
$reg = Invoke-RestMethod -Uri "https://localhost:8443/api/auth/register" `
  -Method POST -ContentType "application/json" `
  -Body '{"email":"smoke@example.test","password":"Smoke1!testpass"}' `
  -SkipCertificateCheck
```

```powershell
# Login and capture token
$login = Invoke-RestMethod -Uri "https://localhost:8443/api/auth/login" `
  -Method POST -ContentType "application/x-www-form-urlencoded" `
  -Body "username=smoke@example.test&password=Smoke1!testpass" `
  -SkipCertificateCheck
$token = $login.access_token
$headers = @{ Authorization = "Bearer $token" }
```

### 4.2 — Quick Scan (expected: HTTP 200)

```powershell
$body = '{"url":"http://example.com"}'
$result = Invoke-RestMethod -Uri "https://localhost:8443/api/scans/quick" `
  -Method POST -Body $body -ContentType "application/json" `
  -Headers $headers -SkipCertificateCheck -TimeoutSec 60
$result | ConvertTo-Json -Depth 5
# Expected fields: url, domain, risk_level, risk_score, is_placeholder, availability, cached
```

### 4.3 — Full (Deep) Scan (expected: HTTP 200, scan_id returned)

```powershell
$body = '{"url":"http://example.com"}'
$result = Invoke-RestMethod -Uri "https://localhost:8443/api/scans/full" `
  -Method POST -Body $body -ContentType "application/json" `
  -Headers $headers -SkipCertificateCheck -TimeoutSec 90
$result | ConvertTo-Json -Depth 5
# Expected fields: scan_id, job_id, status ("QUEUED"), url, queued_at, captured_by
$scanId = $result.scan_id
```

### 4.4 — Poll Scan Status

```powershell
$poll = Invoke-RestMethod -Uri "https://localhost:8443/api/scans/$scanId" `
  -Method GET -Headers $headers -SkipCertificateCheck
$poll | ConvertTo-Json -Depth 5
# Expected: status transitions QUEUED → sandbox_analysis_running → COMPLETE
```

### 4.5 — Dashboard

```powershell
$resp = Invoke-WebRequest -Uri "https://localhost:8443/dashboard/" `
  -SkipCertificateCheck -UseBasicParsing
Write-Host "Dashboard Status: $($resp.StatusCode)"   # Expected: 200
```

### 4.6 — Private IP Rejection (SSRF guard)

```powershell
$body = '{"url":"http://127.0.0.1/"}'
try {
  Invoke-RestMethod -Uri "https://localhost:8443/api/scans/quick" `
    -Method POST -Body $body -ContentType "application/json" `
    -Headers $headers -SkipCertificateCheck -TimeoutSec 15
} catch {
  # Expected: HTTP 400 "URL is unsafe or points to a non-public address"
  Write-Host "Expected 400: $_"
}
```

### 4.7 — Logout / Token Revocation

```powershell
Invoke-RestMethod -Uri "https://localhost:8443/api/auth/logout" `
  -Method POST -Headers $headers -SkipCertificateCheck
# Then verify the token is rejected:
try {
  Invoke-RestMethod -Uri "https://localhost:8443/api/scans" `
    -Headers $headers -SkipCertificateCheck
} catch {
  # Expected: HTTP 401
  Write-Host "Expected 401: $_"
}
```

---

## 5. Fail-Closed Verification

### What "Fail-Closed" Means

When the model worker (`scythe_celery_model_worker`) is unavailable, SCYTHE **must not** return a real risk score. Instead, it returns a placeholder response indicating unavailability. The API still returns **HTTP 200** but with a clearly marked placeholder payload.

### Test Procedure

**Step 1 — Stop the model worker:**
```powershell
docker stop scythe_celery_model_worker
Start-Sleep -Seconds 5
```

**Step 2 — Submit a quick scan:**
```powershell
$body = '{"url":"http://wikipedia.org"}'
$result = Invoke-RestMethod -Uri "https://localhost:8443/api/scans/quick" `
  -Method POST -Body $body -ContentType "application/json" `
  -Headers $headers -SkipCertificateCheck -TimeoutSec 30
$result | ConvertTo-Json -Depth 5
```

**Expected response (fail-closed):**
```json
{
  "url": "http://wikipedia.org/",
  "domain": "wikipedia.org",
  "risk_level": "UNKNOWN",
  "risk_score": null,
  "is_whitelisted": false,
  "model_version": null,
  "contract_version": null,
  "availability": "unavailable",
  "cached": false,
  "is_placeholder": true,
  "reasons": ["Score generated by placeholder model — treat as unverified."],
  "scanned_at": "<timestamp>"
}
```

**Key assertions:**
- `risk_level` = `"UNKNOWN"` ✅ (not a real verdict)
- `risk_score` = `null` ✅ (no numeric score)
- `is_placeholder` = `true` ✅ (explicitly flagged)
- `availability` = `"unavailable"` ✅

### Verified Live Test Results (2026-10-23)

```
Fail-closed test (model worker stopped):
  HTTP 200 | risk_level=UNKNOWN | risk_score=null | is_placeholder=true | availability=unavailable ✅ PASS

Recovery test (model worker restarted and warmed up):
  HTTP 200 | risk_level=SAFE | risk_score=2.46 | is_placeholder=false | availability=observed ✅ PASS
  Target: docs.python.org/3/library/unittest.html -> 2.46% (SAFE)
  Target: en.wikipedia.org/wiki/Phishing -> 0.12% (SAFE)
  Target: 192.168.1.1/admin.html -> 99.82% (PHISHING)
```

**Step 3 — Restart the model worker and verify recovery:**
```powershell
docker start scythe_celery_model_worker
Start-Sleep -Seconds 30   # Allow warm-up; model loading takes ~20–30s
# Run a scan again and confirm is_placeholder=false and risk_score is numeric
```

---

## 6. Dashboard Access

### URLs

| URL | Description |
|---|---|
| `https://localhost:8443/dashboard/` | Main dashboard (redirects to `dashboard.html`) |
| `https://localhost:8443/dashboard/components/dashboard.html` | Direct dashboard page |
| `https://localhost:8443/` | API health check (returns JSON, not HTML) |

### Verified Live (2026-10-23)

| URL | HTTP Status | Content-Type | Size |
|---|---|---|---|
| `https://localhost:8443/dashboard/components/dashboard.html` | **200** ✅ | `text/html` | 892 bytes |
| `https://localhost:8443/` | **200** ✅ | `application/json` | 84 bytes |
| `https://localhost:8443/dashboard/` | **200** ✅ | `text/html` | 892 bytes |

### Auth Steps

The dashboard uses the same JWT auth as the API. You must:
1. Log in via `POST /api/auth/register` + `POST /api/auth/login`
2. Store the `access_token` (the extension and dashboard handle this automatically)
3. All scan API calls require `Authorization: Bearer <token>` header

### TLS / Certificate

- **Development**: Self-signed cert generated by `containers/nginx/generate-ssl.sh` at container startup. Browsers will warn; use `-SkipCertificateCheck` in PowerShell or accept the browser cert warning.
- **Production**: Set `REQUIRE_REAL_CERT=true` in `.env`. The nginx container will reject self-signed certs and expect a valid cert volume-mounted at `/etc/nginx/certs/`.

---

## 7. Alert Pipeline

### How Alerts Flow

```
URL submitted → /api/scans/quick or /api/scans/full
             → Celery task queued on Redis broker
             → celery_worker processes: OCR, vision, sandbox detonation, risk_fusion
             → If risk_level = HIGH/CRITICAL → alert emitted
             → WebSocket push to /ws/user/<user_id>  (real-time dashboard update)
             → Optional: Slack webhook (SLACK_WEBHOOK_URL in .env)
             → Incident record written to Postgres
```

### Verifying Alerts Are Flowing

**Method 1 — Check Celery worker logs:**
```powershell
docker logs scythe_celery_worker --tail 50 -f
# Look for: "risk_fusion completed", "alert dispatched", task SUCCESS/FAILURE lines
```

**Method 2 — Check for incidents in Postgres:**
```powershell
docker exec -i scythe_postgres psql -U postgres -d postgres -c \
  "SELECT id, scan_id, severity, created_at FROM incidents ORDER BY created_at DESC LIMIT 10;"
```

**Method 3 — WebSocket real-time updates:**
Connect to `wss://localhost:8443/ws/user/<user_id>` with a valid JWT auth frame:
```json
{"type": "auth", "token": "<your_access_token>"}
```
After a high-risk scan completes, you should receive a push notification.

### Phishing URL Test Result (2026-10-23)

The test URL `http://paypal.verification-secure.com` returned **HTTP 400** with:
```json
{
  "detail": "URL is unsafe or points to a non-public address: URL host could not be resolved"
}
```
This is **expected behavior** — the sandbox network has no public DNS resolution for test domains. Use a publicly resolvable domain for full alert pipeline testing in production. The SSRF guard correctly rejected the unresolvable hostname.

---

## 8. Recovery Procedures

### Model Worker Down

**Symptoms:** Quick scan returns `is_placeholder=true`, `availability="unavailable"`, `risk_level="UNKNOWN"`.

**Recovery:**
```powershell
# Restart the model worker
docker restart scythe_celery_model_worker

# Wait for healthy status (allow 30s for model loading)
Start-Sleep -Seconds 30
docker inspect --format '{{.State.Health.Status}}' scythe_celery_model_worker

# Verify recovery with a test scan
# Expect: is_placeholder=false, risk_score is a numeric value
```

**If model worker fails to start:**
```powershell
# Check logs for errors
docker logs scythe_celery_model_worker --tail 100

# Common cause: MODEL_RELEASE_CHECKSUMS_SHA256 not set or mismatch
# Resolution: ensure .env has correct MODEL_RELEASE_CHECKSUMS_SHA256
# and MODEL_RELEASE_HOST_DIR points to a valid release bundle directory
```

### Redis Down

**Symptoms:** Celery tasks cannot be queued; API returns 503 or tasks time out.

**Recovery:**
```powershell
docker restart scythe_redis
Start-Sleep -Seconds 10
# Verify
docker exec scythe_redis redis-cli -a "$env:REDIS_PASSWORD" ping
# Expected: PONG
```

> **Note:** Redis uses `--save 60 1` and `--appendonly yes`. On restart, data is restored from the AOF file in the `redis_data` volume. Recent tasks queued in the last 60s may be lost.

### Redis Security (JWT Revocation) Down

**Symptoms:** Logout may silently fail; revoked tokens may temporarily remain valid.

**Recovery:**
```powershell
docker restart scythe_redis_security
Start-Sleep -Seconds 10
docker exec scythe_redis_security redis-cli -a "$env:REDIS_SECURITY_PASSWORD" ping
```

### Postgres Down

**Symptoms:** All API endpoints requiring DB access return 500; auth fails.

**Recovery:**
```powershell
docker restart scythe_postgres
Start-Sleep -Seconds 15
# Backend auto-reconnects on next request (SQLAlchemy connection pool)
docker inspect --format '{{.State.Health.Status}}' scythe_postgres
# Then restart backend to flush stale connections:
docker restart scythe_backend
```

### ClamAV Down (CLAMAV_FAIL_CLOSED=true)

**Symptoms:** File upload endpoints reject all files with an AV error.

**Recovery:**
```powershell
docker restart scythe_clamav
# ClamAV startup takes 60–120s for signature database loading
Start-Sleep -Seconds 90
docker inspect --format '{{.State.Health.Status}}' scythe_clamav
```

### Nginx Down

**Symptoms:** All HTTPS requests fail; `connection refused` on port 8443.

**Recovery:**
```powershell
docker restart scythe_nginx
# Nginx starts in < 5s
```

### Sandbox Runner Down

**Symptoms:** Full scans queue but never progress; `sandbox_analysis_running` status hangs.

**Recovery:**
```powershell
docker restart scythe_sandbox_runner
docker logs scythe_sandbox_runner --tail 50
```

### Full Stack Restart

```powershell
cd "C:\Users\armaa\Desktop\Project details\SCYTHE"
docker compose --profile shadow --profile models down
docker compose --profile shadow --profile models up -d
# Wait for all services to be healthy (~60–90s)
Start-Sleep -Seconds 90
docker ps --format "table {{.Names}}\t{{.Status}}"
```

---

## 9. Known Limitations

### Model Worker / Scoring

| Limitation | Detail |
|---|---|
| **Placeholder fallback** | When `MODEL_RELEASE_ENABLED=true` but the model worker is unavailable or the model fails to load, the system returns `UNKNOWN`/`is_placeholder=true`. This is intentional fail-closed behavior. |
| **MODEL_RELEASE_CHECKSUMS_SHA256 required** | If this env var is not set or does not match the release bundle, the model worker will refuse to load the v26 model and fall back to placeholder. Set it to the SHA256 content of `models/releases/checksums.sha256`. |
| **v21 qualification status** | Model `candidate_fusion_v26` is `status: validated` per `release.json` with `approved_policy.json` (`status: approved`). Retrained on 176,522 balanced samples across 65,382 domains with domain-disjoint split. Evaluated ROC-AUC: 0.9624, PR-AUC: 0.9451, Test FPR: 0.39%–0.67%. Verified live under trust anchor `6fe3b2e3a357967ee8b524fe26df645afb1e203ce93c485ec5468d0bf2b8fae1`. Passed `scripts/model_release_readiness.py` with 0 blockers (`production_ready: true`). |
| **MobileCLIP visual model** | `MOBILECLIP_ENABLED=false` by default. Not activated until checkpoint, vendor source, classifier artifact, and CPU inference dependencies are installed and reviewed. Do not enable without completing the visual model qualification gate. |
| **Shadow worker** | `SHADOW_SCORING_ENABLED=false` by default. Requires `COMPOSE_PROFILES=shadow` and explicit opt-in. Experimental; not production-ready. |

### Network / Sandbox

| Limitation | Detail |
|---|---|
| **DNS in sandbox** | The sandbox network (`scythe_sandbox_net`) has no public DNS resolution by default. URLs with unresolvable hostnames receive HTTP 400 with "URL host could not be resolved". This is by design (SSRF protection + network isolation). |
| **Docker socket proxy scope** | `scythe_socket_proxy` exposes `CONTAINERS=1 + POST=1 + IMAGES=1`. A compromised `sandbox_runner` could theoretically stop/start any container on the Docker daemon. Mitigation: use a dedicated rootless Docker context for the sandbox in high-security deployments. |

### TLS / Auth

| Limitation | Detail |
|---|---|
| **Self-signed cert** | Dev uses a self-signed cert. Browsers will show a security warning. The Chrome extension makes direct HTTPS calls to `localhost:8443`; users must accept the cert in browser settings or install it as trusted. |
| **CORS + extension ID** | The Chrome extension's origin (`chrome-extension://<id>`) must be explicitly added to `CORS_ALLOWED_ORIGINS` in `.env`. If not set, extension → API calls will fail with CORS errors. |
| **Production host validation** | In `ENVIRONMENT=production`, `ALLOWED_HOSTS` must not contain only internal hostnames (`localhost`, `127.0.0.1`, `backend`, `nginx`) — the app will refuse to start. |

### Data / Artifacts

| Limitation | Detail |
|---|---|
| **Scan artifact volume** | Scan files (screenshots, DOM captures) accumulate in `shared/scans/`. `celery_beat` runs periodic cleanup, but no hard limit is enforced. Monitor disk usage in production. |
| **Redis `noeviction` policy** | Both Redis instances use `maxmemory-policy noeviction`. If memory is exhausted, Redis will return errors instead of evicting keys. Monitor memory usage and adjust `maxmemory` limits in `docker-compose.yml` as needed. |

---

## Appendix A — Container Summary

| Container | Image | Port (internal) | Profile |
|---|---|---|---|
| `scythe_nginx` | `scythe-nginx` | 80/443 (→ host 8080/8443) | default |
| `scythe_backend` | `scythe-backend` | 8000 | default |
| `scythe_redis` | `scythe-redis:7.2-alpine-hardened` | 6379 | default |
| `scythe_redis_security` | `scythe-redis:7.2-alpine-hardened` | 6379 | default |
| `scythe_postgres` | `postgres:16-alpine` | 5432 | default |
| `scythe_clamav` | *(vendor)* | 3310 | default |
| `scythe_socket_proxy` | `scythe-socket-proxy:v0.5.0-hardened` | 2375 | default |
| `scythe_sandbox_net_holder` | *(network placeholder)* | — | default |
| `scythe_celery_worker` | `scythe-backend` (worker) | — | default |
| `scythe_celery_beat` | `scythe-backend` (beat) | — | default |
| `scythe_sandbox_runner` | `scythe-sandbox` | 8002 | default |
| `scythe_celery_model_worker` | `scythe-backend` (model) | — | `models` |
| `scythe_celery_shadow_worker` | `scythe-backend` (shadow) | — | `shadow` |

## Appendix B — API Endpoint Reference

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/register` | None | Register new user |
| `POST` | `/api/auth/login` | None (form) | Login → JWT |
| `POST` | `/api/auth/logout` | Bearer | Revoke token |
| `POST` | `/api/scans/quick` | Bearer | Quick URL scan |
| `POST` | `/api/scans/full` | Bearer | Full/deep scan (async) |
| `GET` | `/api/scans/<scan_id>` | Bearer | Poll scan status |
| `GET` | `/api/scans` | Bearer | Scan history |
| `POST` | `/api/scans/manual-url` | Bearer | Manual URL submission |
| `POST` | `/api/email/investigate` | Bearer | Email analysis |
| `GET` | `/` | None | Health check |
| `WS` | `/ws/scan/<scan_id>` | JWT frame | Scan real-time updates |
| `WS` | `/ws/user/<user_id>` | JWT frame | User real-time alerts |

> **Note:** The API prefix is `/api/scans/` — not `/api/v1/scan/`. FastAPI docs are available at `/docs` when `DEBUG=true` (dev only).

## Appendix C — Model Release Bundle

**Location:** `models/releases/`  
**Model version:** `candidate_fusion_v26`  
**Feature contract:** `scythe_fusion_v2`  
**Status:** `validated` / `approved`

| Path | SHA256 |
|---|---|
| `quick_classifier.txt` | `c60cd7b7...` |
| `deep_classifier.txt` | `dce17260...` |
| `feature_contract.json` | `b5a4065c...` |
| `approved_policy.json` | `a26a6081...` |
| `thresholds.json` | `ebedbfee...` |

**Quality metrics (Wilson 95% CI):**
- Quick URL: recall 85–99%, FPR 0.1–0.8%
- Deep URL: recall 99–100%, FPR 0.0–0.18%

To activate with checksum verification, set in `.env`:
```
MODEL_RELEASE_ENABLED=true
MODEL_RELEASE_CHECKSUMS_SHA256=<sha256 of models/releases/checksums.sha256 file>
```
