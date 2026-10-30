# SCYTHE: Secure Cyber & Threat Heuristics Engine

> **Enterprise-grade, containerized automated phishing detection, threat intelligence, and behavioral sandboxing platform.**  
> SCYTHE intercepts, sandboxes, and dissects malicious URLs and email payloads — exposing sophisticated cloaking and credential harvesting before end users can be compromised.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Production Readiness](https://img.shields.io/badge/Production_Readiness-QUALIFIED-brightgreen.svg)]()
[![Model Version](https://img.shields.io/badge/Model-candidate__fusion__v26-success.svg)]()
[![Smoke Tests](https://img.shields.io/badge/Smoke_Tests-16%2F16_PASSED-brightgreen.svg)]()
[![OWASP Top 10](https://img.shields.io/badge/OWASP_Top_10-PASSED-green.svg)]()
[![Security Audits](https://img.shields.io/badge/Security_Audits-0_Critical_CVEs-brightgreen.svg)]()

---

## 1. System Overview

SCYTHE provides multi-tier, defense-in-depth protection across browser navigation, manual dashboard analysis, and enterprise email ingestion. It eliminates single-point-of-failure heuristic detection by combining deterministic threat intelligence, sandboxed browser execution, consistency checks, and calibrated machine learning into an automated verification pipeline.

```
                           [ Chrome Extension (MV3) ]
                                       │
                                       ▼
                          [ Nginx TLS 1.3 Proxy (:8443) ]
                                       │
                          [ FastAPI Backend (:8000) ]
                                       │
             ┌─────────────────────────┴─────────────────────────┐
             ▼                                                   ▼
    [ Stage 1: Quick Scan ]                            [ Stage 2: Deep Scan ]
    ├─ Domain Allowlist Cache                          ├─ Celery Chord Orchestrator
    ├─ CyberIntel Feeds (VT, OTX)                      ├─ Isolated gVisor Sandbox
    └─ LightGBM URL Classifier                         ├─ DOM & Network HAR Extraction
                                                       ├─ Consistency Engine (Anti-Cloaking)
                                                       └─ Multimodal Risk Fusion Engine
```

### Core Capabilities

* **Pre-Flight Quick Scans (`/api/scans/quick`):** Synchronous sub-second threat scoring powered by domain allowlists, CyberIntel integrations, and calibrated LightGBM URL behavioral models. Accurately flags benign domains as `SAFE` and malicious IP-hosted phishing campaigns as `HIGH`.
* **Ephemeral gVisor Sandboxing (`scythe-sandbox:v1.0.0`):** Detonates untrusted URLs inside disposable, sandboxed Chromium instances run under Google gVisor (`runsc`) with dropped Linux capabilities (`cap_drop: ALL`).
* **Consistency Engine (Anti-Cloaking):** Compares the user browser's viewport and DOM against clean sandbox detonations to detect geolocation filtering, user-agent cloaking, and CAPTCHA wall obfuscation.
* **4-Way Parallel Email Analysis (`/api/email/investigate`):** Parses RFC822 messages and executes a 4-branch Celery chord across header authentication (SPF/DKIM/DMARC), embedded URL threat modeling, ClamAV antivirus attachment scanning, and linguistic content analysis.
* **Fail-Closed Machine Learning:** Models verify tamper-evident cryptographic checksum manifests prior to deserialization; any unverified, missing, or malformed artifact immediately fails closed to `UNKNOWN` (`is_placeholder: true`).

---

## 2. Machine Learning Architecture (`candidate_fusion_v26`)

The SCYTHE production inference pipeline runs on the audited and verified `candidate_fusion_v26` multimodal architecture under contract `scythe_fusion_v2`.

```
           ┌───────────────────────────────────────────────┐
           │          Candidate Fusion V26 Pipeline        │
           └───────────────────────┬───────────────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         ▼                                                   ▼
[ Quick Path (URL Only) ]                           [ Deep Path (Multimodal) ]
├─ 15 Morphological URL Features                    ├─ URL Sub-Model Predictions
├─ Standalone LightGBM Classifier                   ├─ 512-d MobileCLIP L2 Visual Embeddings
├─ Calibrated Leaf Fallback (threshold=0.50)        ├─ 99.33% Backfilled DOM/Form Counts
│  • Benign: 0.13 - 0.96 (SAFE)                     ├─ Authoritative DNS & WHOIS Features
│  • Phishing: 99.97 (HIGH)                         └─ Sandbox Cross-Domain Form Ratios
└─ Persistent Volume Mount (`scythe_bundle_v26`)
```

### Inference Fallback & Calibration
In standalone Quick URL scans where DOM and sandbox telemetry are not yet observed (`NaN`), the fusion model output is calibrated in `tasks/model_inference.py`:
* When degenerate constant leaf output (`~0.9717`) is detected due to absent DOM/sandbox signals, the pipeline automatically falls back to the specialized LightGBM URL classifier (`url_classifier.txt`).
* URLs scoring `< 0.50` are marked `SAFE` (e.g., `bbc.com` → 0.13, `python.org` → 0.14, `reddit.com` → 0.14, `stackoverflow.com` → 0.96).
* Malicious infrastructure scores `> 0.50` and is flagged `HIGH` (e.g., direct-IP phishing campaigns → 99.97).
* All outputs strictly satisfy schema validation: `probability ∈ [0, 1]` and `risk_score = round(probability * 100, 2)`.

### Dataset & Training Rigor
* **Sanitized 10,000-Row Dataset:** 5,000 phishing and 5,000 benign multimodal records in `manifest_paired_10k.jsonl` (SHA-256: `13f753e92f069cee6d63921defa3a0aa470cd647156562b6362a06bbc26dc6a0`).
* **Zero Cross-Split Leakage:** 0 domain overlaps and 0 screenshot image SHA-256 overlaps between the 8,000 training and 2,000 validation records.
* **DOM Feature Completeness:** Backfilled from raw HTML archives to **99.33%** (`browser_dom_form_count`, `browser_dom_script_count`, `browser_dom_link_count`, `sandbox_cross_domain_form_count`).

### Holdout Evaluation & Metrics (7,082 URLs)
Evaluated across **7,082 holdout URLs** (2,050 phishing, 5,032 benign) with **14,164 total model evaluations** and **28,466 content-addressed evidence blobs**:

| Metric | Quick Scan Path | Deep Scan Path | Target Policy | Pass Status |
|---|:---:|:---:|:---:|:---:|
| **Recall** | **86.59%** | **86.59%** | $\ge 80.0\%$ | **PASS** |
| **Wilson-95 Lower Bound (Recall)** | **0.8504** | **0.8504** | $\ge 0.8000$ | **PASS** |
| **False Positive Rate** | **0.00%** (0 / 5,032) | **0.00%** (0 / 5,032) | $\le 1.0\%$ | **PASS** |
| **Wilson-95 Upper Bound (FPR)** | **0.000760** (~7.6 / 10k) | **0.000760** (~7.6 / 10k) | $\le 0.0100$ (100 / 10k) | **PASS** |
| **p95 Latency** | **176.92 ms** | **551.88 ms** | $\le 2,000$ ms / $\le 15,000$ ms | **PASS** |
| **Coverage** | **100.0%** | **100.0%** | $100.0\%$ | **PASS** |
| **PR-AUC** | **1.0000** | **1.0000** | $\ge 0.9000$ | **PASS** |
| **Brier Score** | **0.0419** | **0.0466** | $\le 0.1000$ | **PASS** |

* **Cryptographic Trust Anchor:** `6fe3b2e3a357967ee8b524fe26df645afb1e203ce93c485ec5468d0bf2b8fae1`  
* **Manifest Verified Files:** **28,485 files** (100% cryptographic checksum match prior to activation).

---

## 3. Container Topology & Storage Architecture

SCYTHE deploys as 13 hardened, interoperating Docker containers communicating over isolated internal bridge networks:

| Container Name | Service Role | Security & Hardening |
|---|---|---|
| `scythe_nginx` | Reverse Proxy & TLS Termination | Port 8443 (TLS 1.3/1.2), strict CSP, HSTS, X-Frame-Options, rate limiting (`10r/m`). |
| `scythe_backend` | FastAPI Application Server | Uvicorn, non-root `UID 10001`, SQLAlchemy parameterized queries, JWT validation. |
| `scythe_celery_model_worker` | ML Inference Engine | Pinned queue `models`, pre-warmed memory cache, fail-closed deserialization. |
| `scythe_celery_worker` | General Async Task Runner | Prefork worker, chord orchestrator, `max_tasks_per_child=100`. |
| `scythe_celery_beat` | Periodic Task Scheduler | Persistent schedule database in isolated volume. |
| `scythe_celery_shadow_worker` | Diagnostic / Shadow Scorer | Evaluates secondary models without affecting production incident decisions. |
| `scythe_redis` | Primary Task Broker & Scan Cache | Password authenticated, DB 0 (broker), DB 1 (cache), non-root execution. |
| `scythe_redis_security` | Token Blacklist & Rate Limits | Dedicated isolated Redis instance for security-critical token revocation. |
| `scythe_postgres` | Relational Metadata Storage | PostgreSQL 16, tenant isolation via row-level ownership checks, bcrypt hashing. |
| `scythe_clamav` | Antivirus Daemon | ClamD socket daemon (port 3310), daily automated signature updates. |
| `scythe_socket_proxy` | Docker Daemon Firewall | Restricts Docker API access; blocks unauthorized container creation or volume escape. |
| `scythe_sandbox_runner` | Detonation Controller | Ephemeral container lifecycle manager via gVisor runtime. |
| `scythe_sandbox_net_holder` | Network Namespace Gateway | Network sandbox boundary holder for controlled egress inspection. |

### Persistent Model Volume (`scythe_bundle_v26`)
* **Decoupled Model Storage:** The full 28,485-file model release bundle (~2 GB) is housed in the named Docker volume `scythe_bundle_v26` and mounted at `/opt/scythe/bundle` in both `scythe_backend` and `scythe_celery_model_worker`.
* **Container Lifecycle Persistence:** Image builds remain lightweight and code updates can be baked into container images without re-copying or re-downloading model artifacts.
* **External Volume Declaration:** Registered in `docker-compose.yml` with `external: true` to prevent accidental pruning or recreate warnings.

---

## 4. Security & Compliance Matrix (OWASP Top 10)

SCYTHE has completed comprehensive security verification with zero critical CVEs and passed OWASP Top 10 controls:

* **A01: Broken Access Control:** Strict tenant-isolated database queries (`scan.owner_id == user.id`), cross-tenant queries return 404 (IDOR prevention verified).
* **A02: Cryptographic Failures:** Bcrypt password hashing (work factor 12), memory-only secret handling, automated Gitleaks scan in CI/CD with 0 leaks across repository history.
* **A03: Injection:** Pure SQLAlchemy ORM parameterization (zero raw SQL), Pydantic input models, Chromium running under gVisor `runsc`.
* **A04: Insecure Design:** Defense-in-depth, fail-closed ML model gate (`ReleaseUnavailable` fallback), rate-limited authentication routes.
* **A05: Security Misconfiguration:** Hardened security headers (`nosniff`, `DENY`, HSTS), production debug mode disabled, non-root user execution (`UID 10001`).
* **A06: Vulnerable Components:** Dependencies pinned with SHA-256 hashes; `pip-audit` confirms 0 known vulnerabilities.
* **A07: Identification Failures:** JWT HMAC-SHA256 with expiration, atomic server-side revocation in Redis, tokens stored in `sessionStorage` (XSS resistant).
* **A08: Software & Data Integrity:** Checksum manifests verify all 28,485 release files against anchor `6fe3b2e3...` before loading native models into memory.
* **A09: Logging Failures:** Structured Loguru JSON logging with PII/secret scrubbing (`LOG_REDACTION_ENABLED`), Prometheus `/metrics` latency monitoring.
* **A10: SSRF Protection:** Pre-resolves DNS, blocks RFC 1918 private IPs, RFC 4193 bogons, loopback addresses (`127.0.0.1`), and AWS/GCP metadata endpoints (`169.254.169.254`).

---

## 5. Quick Start & Local Operations

### Prerequisites
* Docker Engine 24+ & Docker Compose v2
* 8 GB+ RAM recommended
* Python 3.11+ (for local test client scripts)

### Installation & Launch

```bash
# 1. Clone repository
git clone https://github.com/your-org/SCYTHE.git
cd SCYTHE

# 2. Configure environment
cp .env.example .env

# 3. Create and populate persistent model volume (if not already created)
docker volume create scythe_bundle_v26
docker run --rm -v scythe_bundle_v26:/dest -v "$(pwd)/models/releases/candidate_fusion_v26:/src:ro" alpine sh -c "cp -a /src/. /dest/"

# 4. Build and launch all 13 containers with the models profile
docker compose --profile models up --build -d

# 5. Verify all containers are healthy
docker ps --format "table {{.Names}}\t{{.Status}}"
```

### Warm Up the Model Inference Worker
Cold verification of the 28,485 cryptographic release files runs on startup. You can warm and prime the in-memory cache at any time via:

```bash
docker exec scythe_backend python -m tasks.model_inference
```

Output confirms trust anchor match and paths initialized:
```json
{"status": "warmed", "model_version": "candidate_fusion_v26", "release_manifest_sha256": "6fe3b2e3a357967ee8b524fe26df645afb1e203ce93c485ec5468d0bf2b8fae1", "warmed_paths": ["quick_url", "deep_url"], "elapsed_ms": 37825.852}
```

### Running Scans via HTTPS API

```bash
# Generate test JWT token and execute a quick scan
curl -k -X POST https://localhost:8443/api/scans/quick \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.bbc.com/"}'
```

Expected response:
```json
{
  "url": "https://www.bbc.com/",
  "domain": "www.bbc.com",
  "risk_level": "SAFE",
  "risk_score": 0.13,
  "is_whitelisted": false,
  "model_version": "candidate_fusion_v26",
  "contract_version": "scythe_fusion_v2",
  "availability": "observed",
  "cached": false,
  "is_placeholder": false,
  "reasons": []
}
```

---

## 6. Test Suites & Verification

SCYTHE includes automated end-to-end smoke test suites verifying the full platform:

### 1. Full Model & Quick Scan Smoke Test (`smoke_test_suite.py`)
Executes 16 comprehensive live checks against the running containers:
* **Auth Gate:** Unauthenticated requests return `401 Unauthorized`.
* **Allowlist Enforcement:** `wikipedia.org`, `wikimedia.org` return `SAFE` + `is_whitelisted: true` immediately without model invocation.
* **Non-Whitelisted Benign Domains:** Verified benign sites score strictly `SAFE`:
  * `bbc.com` (0.13)
  * `python.org` (0.14)
  * `reddit.com` (0.14)
  * `stackoverflow.com` (0.96)
  * `github.com` (0.00)
* **Phishing Detection:** Known hostile IP phishing URLs score `HIGH` (99.97):
  * `http://101.99.90.128/...`
  * `http://101.99.90.131/...`
  * `http://101.99.90.132/...`
  * `http://101.99.90.147/...`
  * `http://101.99.90.156/...`
* **Release Contract Integrity:** Confirms active `model_version == "candidate_fusion_v26"` with `is_placeholder == false`.

```bash
python smoke_test_suite.py
# Output: RESULT: 16/16 checks passed — ALL CHECKS PASSED
```

### 2. Frontend & Dashboard Session Smoke Test (`scripts/frontend_workflow_smoke.py`)
Validates 8 core UI workflow checks:
* JWT session storage & retrieval
* Multi-tenant history isolation
* DOM inspection and scan report rendering

```bash
python scripts/frontend_workflow_smoke.py
```

### 3. Parallel Email & Celery Chord Smoke Test (`scripts/email_workflow_smoke.py`)
Validates 22 async email engine checks:
* RFC822 MIME parsing & email header authentication (SPF/DKIM/DMARC)
* Parallel Celery chord fanout & reconciliation
* ClamAV daemon attachment scanning & quarantine

```bash
python scripts/email_workflow_smoke.py
```

---

## 7. Project Structure

```
SCYTHE/
├── chrome-extension/         # Manifest V3 extension (service worker, BDR heuristics, warning DOM)
├── containers/
│   ├── backend/              # FastAPI core, SQLAlchemy models, Celery tasks, and feature extractors
│   ├── nginx/                # Reverse proxy configuration and TLS certificate generation
│   ├── postgres/             # Database initialization and migration scripts
│   ├── sandbox/              # gVisor Chromium isolated detonation environment
│   └── vendor/               # Hardened Redis base configurations
├── dashboard/                # React dashboard (scan submission, incident review, history)
├── docs/                     # Full qualification audits, threat logs, and operator protocols
├── models/
│   └── releases/             # Verified release bundles (candidate_fusion_v26)
├── scripts/                  # Workflow smoke tests, security scanners, and deploy utilities
├── smoke_test_suite.py       # Automated 16-point live end-to-end qualification test suite
└── docker-compose.yml        # Multi-service composition orchestrator
```

---

*SCYTHE: Automated threat heuristics, resilient defenses, zero trust by design.*
