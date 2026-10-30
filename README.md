# SCYTHE: Secure Cyber & Threat Heuristics Engine

> **Enterprise-grade, containerized automated phishing detection, threat intelligence, and behavioral sandboxing platform.**  
> SCYTHE intercepts, sandboxes, and dissects malicious URLs and email payloads — exposing sophisticated cloaking and credential harvesting before end users can be compromised.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Production Readiness](https://img.shields.io/badge/Production_Readiness-QUALIFIED-brightgreen.svg)]()
[![Model Version](https://img.shields.io/badge/Model-candidate__fusion__v26-success.svg)]()
[![Challenger Model](https://img.shields.io/badge/Challenger-candidate__fusion__v27_experimental-yellow.svg)]()
[![Smoke Tests](https://img.shields.io/badge/Smoke_Tests-16%2F16_PASSED-brightgreen.svg)]()
[![OWASP Top 10](https://img.shields.io/badge/OWASP_Top_10-PASSED-green.svg)]()
[![Security Audits](https://img.shields.io/badge/Security_Audits-0_Critical_CVEs-brightgreen.svg)]()
[![Training Scale](https://img.shields.io/badge/Training_Scale-428K_URLs_%7C_22K_Images-blue.svg)]()

---

## 1. System Overview

SCYTHE provides multi-tier, defense-in-depth protection across browser navigation, manual dashboard analysis, and enterprise email ingestion. It eliminates single-point-of-failure heuristic detection by combining deterministic threat intelligence, sandboxed browser execution, consistency checks, and calibrated machine learning into an automated verification pipeline.

```
                         [ Chrome Extension (MV3) ]
                                     |
                        [ Nginx TLS 1.3 Proxy (:8443) ]
                                     |
                        [ FastAPI Backend (:8000) ]
                                     |
             +-----------------------+------------------------+
             |                                               |
    [ Stage 1: Quick Scan ]                    [ Stage 2: Deep Scan ]
    - Domain Allowlist Cache                   - Celery Chord Orchestrator
    - CyberIntel Feeds (VT, OTX)               - Isolated gVisor Sandbox
    - LightGBM URL Classifier                  - DOM & Network HAR Extraction
                                               - Consistency Engine (Anti-Cloaking)
                                               - Multimodal Risk Fusion Engine
```

### Core Capabilities

* **Pre-Flight Quick Scans (`/api/scans/quick`):** Synchronous sub-second threat scoring powered by domain allowlists, CyberIntel integrations, and calibrated LightGBM URL behavioral models. Accurately flags benign domains as `SAFE` and malicious IP-hosted phishing campaigns as `HIGH`.
* **Ephemeral gVisor Sandboxing (`scythe-sandbox:v1.0.0`):** Detonates untrusted URLs inside disposable, sandboxed Chromium instances run under Google gVisor (`runsc`) with dropped Linux capabilities (`cap_drop: ALL`).
* **Consistency Engine (Anti-Cloaking):** Compares the user browser's viewport and DOM against clean sandbox detonations to detect geolocation filtering, user-agent cloaking, and CAPTCHA wall obfuscation.
* **4-Way Parallel Email Analysis (`/api/email/investigate`):** Parses RFC822 messages and executes a 4-branch Celery chord across header authentication (SPF/DKIM/DMARC), embedded URL threat modeling, ClamAV antivirus attachment scanning, and linguistic content analysis.
* **Fail-Closed Machine Learning:** Models verify tamper-evident cryptographic checksum manifests prior to deserialization; any unverified, missing, or malformed artifact immediately fails closed to `UNKNOWN` (`is_placeholder: true`).

---

## 2. Machine Learning Architecture

### Production Release: `candidate_fusion_v26`

The SCYTHE production inference pipeline runs on the audited and verified `candidate_fusion_v26` multimodal architecture under contract `scythe_fusion_v2`.

```
        +--------------------------------------------------+
        |         Candidate Fusion V26 Pipeline            |
        +--------------------+-----------------------------+
                             |
           +-----------------+----------------+
           |                                  |
   [ Quick URL Head ]               [ Deep URL Head ]
   LightGBM (178K params)          LightGBM (355K params)
   p95 latency: ~177ms             p95 latency: ~552ms
           |                                  |
           +--------+          +--------------+
                    |          |
             [ Visual Head ]  [ Scythe Observations ]
             MobileCLIP S0     Browser features, sandbox
             512-dim L2        signals, consistency score
                    |
              [ Risk Fusion ]
              Calibrated weighted ensemble
```

**Qualification Gates (Independent 7,082-Sample Holdout):**
- Phishing Recall (Wilson-95): ≥ 86.6%
- False Positive Rate: 0% observed
- Quick URL p95 Latency: 177ms
- Deep URL p95 Latency: 552ms
- Availability: 100%

### Experimental Challenger: `candidate_fusion_v27`

> **Status**: `experimental_challenger` — NOT production-qualified. Runs in shadow scoring only; `v26` remains the live release.

Trained at massive scale on **October 31, 2026** using decoupled, modality-independent training:

| Modality | Training Scale | Key Metric | Gain vs v26 Baseline |
|:---|:---|:---|:---|
| **URL Classifier** | **428,222 URLs** (147,798 phishing + 280,424 benign) | ROC-AUC: **0.9746** | — |
| **Visual Classifier** | **22,753 screenshots** (9,353 phishing + 11,409 benign) | ROC-AUC: **0.9232** | **+7.36%** |

Additional v27 gains vs v26 visual baseline:
- **PR-AUC**: 0.8818 vs 0.7456 (**+13.62%**)
- **Recall**: 87.31% vs 72.93% (**+14.38%**)
- **Live PaaS phishing attack detection**: `phantom-app-4eu8.vercel.app` → **100% HIGH RISK** (with new 18-feature PaaS signal contract)

---

## 3. Security Posture

### OWASP Top 10 Audit (October 31, 2026)

| OWASP Category | Status | Evidence |
|:---|:---|:---|
| **A01 Broken Access Control** | ✅ PASS | 0 unprotected endpoints; all routes require auth tokens |
| **A02 Cryptographic Failures** | ✅ PASS | JWT pinned to HS256; Bcrypt salted password hashing; TLSv1.3 enforced; HSTS active |
| **A03 Injection** | ✅ PASS | 0 raw SQL interpolations (SQLAlchemy parameterized); 0 `shell=True` calls |
| **A05 Security Misconfiguration** | ✅ PASS | Non-root `scythe` user enforced in containers; no exposed internal ports |
| **A08 Data Integrity** | ✅ PASS | SHA-256 trust anchor `6fe3b2e3...`; inference uses `json.load` + dot product only |
| **A10 SSRF** | ✅ PASS | `url_policy.py` pre-resolves DNS once; blocks RFC1918, 127.0.0.1, 169.254.169.254, multicast |

**Dependency Scan:** 0 known CVEs across all `requirements.txt` files (pip-audit, Oct 31 2026).  
**Secret Scan:** 0 secrets detected (gitleaks).  
**SAST:** 0 high-severity findings (Bandit).

### Container Hardening
- 6/9 Dockerfiles run as unprivileged user `scythe`
- Nginx enforces TLSv1.3, disables TLSv1.0, and sends HSTS headers
- Redis secured via `requirepass` with unique credentials per service
- Docker socket access locked behind `scythe_socket_proxy` (allowlist-only)

---

## 4. Model Governance & Release Audit

SCYTHE enforces immutable, cryptographically-bound model releases. No model can serve production traffic without a verified trust anchor.

### v26 Release Evidence Bundle

| Artifact | SHA-256 | Location |
|:---|:---|:---|
| `checksums.sha256` (trust anchor) | `6fe3b2e3a357967ee8b524fe26df645afb1e203ce93c485ec5468d0bf2b8fae1` | `models/releases/candidate_fusion_v26/` |
| `holdout.jsonl` (7,082 samples) | `d52d5c3e0ac21a245c772148ac2b89df521af8e203c4a78ca5266ef8730682b8` | `evidence/` |
| `independent_evidence.jsonl` | `90b328d0c83beeff372a48a0f6197304782d83dc9db5117fb6c5e5a9e5a26fee` | `evidence/` |
| `REVIEWER_ATTESTATION.md` | `cfed54e1a640b279eb0ee9c5b446e7674ae92e666c89632797191a1495a4d493` | `evidence/` |
| `REVIEW_DECISIONS.jsonl` (7,633 records) | `611e1c1abfb3a3dae78cb0a4ddb898aaaea92c47c223a20572fd6160fe5dc714` | `evidence/` |

### Training Exclusion Verification (pyarrow-verified, Oct 31 2026)

```
train split:      155,609 rows  |  0 excluded URL hits  |  0 excluded domain hits
validation split:  38,902 rows  |  0 excluded URL hits  |  0 excluded domain hits
cross-split domain overlap: 0
status: VERIFIED
```

---

## 5. Quick Start

### Prerequisites
- Docker Desktop with Linux containers
- Docker Compose v2+
- Python 3.11+ (for smoke tests and scripts only)

### Local Deployment

```bash
# 1. Clone the repository
git clone https://github.com/armaan-1207/SCYTHE.git
cd SCYTHE

# 2. Configure your local environment
cp .env.example .env
# Edit .env with your secrets (SECRET_KEY, DB password, Redis password, etc.)

# 3. Populate the model bundle volume
docker volume create scythe_bundle_v26
docker run --rm \
  -v scythe_bundle_v26:/dest \
  -v "$(pwd)/models/releases/candidate_fusion_v26:/src:ro" \
  alpine sh -c "cp -a /src/. /dest/"

# 4. Launch all 13 containers with the models profile
docker compose --profile models up --build -d

# 5. Verify all containers are healthy
docker ps --format "table {{.Names}}\t{{.Status}}"
```

### Verifying the Production Model

```bash
# Confirm the model bundle is loaded and trust anchor matches
docker exec scythe_backend python -c "
from services.model_release import verify_release
from config import settings
root, rel, contract, pol, hashes = verify_release('/opt/scythe/bundle', settings.MODEL_RELEASE_CHECKSUMS_SHA256)
print('SUCCESS! Bundle verified:', rel.get('model_version'))
"
# Expected: SUCCESS! Bundle verified: candidate_fusion_v26

# Run the model release readiness audit
python scripts/model_release_readiness.py \
  --output docs/readiness_check.json \
  --policy models/releases/candidate_fusion_v26/approved_policy.json \
  --release-bundle models/releases/candidate_fusion_v26 \
  --release-checksums-sha256 6fe3b2e3a357967ee8b524fe26df645afb1e203ce93c485ec5468d0bf2b8fae1
# Expected: {"production_ready": true, "blocker_count": 0}
```

### Submitting a Scan

```bash
# 1. Obtain a JWT (replace credentials with your test user)
TOKEN=$(curl -sk -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@example.test","password":"your-password"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 2. Execute a quick URL scan
curl -sk -X POST https://localhost:8443/api/scans/quick \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.bbc.com/"}'
```

Expected response:
```json
{
  "url": "https://www.bbc.com/",
  "risk_level": "SAFE",
  "risk_score": 0.13,
  "model_version": "candidate_fusion_v26",
  "availability": "observed",
  "is_placeholder": false
}
```

---

## 6. Test Suites & Verification

All suites run against the live Docker stack. Run `docker compose --profile models up -d` before executing.

### End-to-End Smoke Test Suite (Oct 31, 2026 — all PASSED)

| Suite | Checks | Result | Report |
|:---|:---|:---|:---|
| **Live Model Smoke** (`smoke_test_suite.py`) | 16/16 | ✅ PASS | Live phishing scored 99.97%; model `candidate_fusion_v26` confirmed |
| **Frontend Workflow** (`scripts/frontend_workflow_smoke.py`) | 8/8 | ✅ PASS | `docs/frontend_workflow_smoke_20261031_current.json` |
| **Email Workflow** (`scripts/email_workflow_smoke.py`) | 22/22 | ✅ PASS | `docs/email_workflow_smoke_20261031_current.json` |
| **Frontend UI Contract** (`scripts/test_frontend_ui.py`) | All API calls authorized | ✅ PASS | `docs/frontend_ui_test_20261031.json` |
| **Extension Auth Bridge** (`scripts/test_extension_auth.cjs`) | Auth, expiry, revocation | ✅ PASS | Inline |

```bash
# Run all suites
python smoke_test_suite.py
python scripts/frontend_workflow_smoke.py --output docs/frontend_workflow_smoke_latest.json
python scripts/email_workflow_smoke.py --output docs/email_workflow_latest.json --allow-local-self-signed
node scripts/test_extension_auth.cjs
```

### Security Scans

```bash
# OWASP Top 10 audit
python scripts/owasp_audit.py

# SAST, dependency CVE scan, and container image scan
python scripts/security_scan.py

# Sandbox image digest drift check
python scripts/check_digest_drift.py
```

### Release Readiness

```bash
python scripts/model_release_readiness.py \
  --output docs/readiness.json \
  --policy models/releases/candidate_fusion_v26/approved_policy.json \
  --release-bundle models/releases/candidate_fusion_v26 \
  --release-checksums-sha256 6fe3b2e3a357967ee8b524fe26df645afb1e203ce93c485ec5468d0bf2b8fae1
```

---

## 7. Project Structure

```
SCYTHE/
├── chrome-extension/         # Manifest V3 extension (MV3 service worker, auth bridge, warning DOM)
├── containers/
│   ├── backend/              # FastAPI core, SQLAlchemy models, Celery tasks, feature extractors
│   │   ├── ai_engine/        # OCR, visual scoring, DOM extraction
│   │   ├── api/              # REST routes (scans, email, auth)
│   │   ├── auth/             # JWT, Bcrypt, token revocation
│   │   ├── services/         # Model release loader, SSRF policy, risk fusion
│   │   └── tasks/            # Celery tasks: sandbox, browser, email, model inference
│   ├── nginx/                # TLS 1.3 reverse proxy and HSTS configuration
│   ├── postgres/             # Database init and Alembic migrations
│   ├── sandbox/              # gVisor Chromium isolated detonation environment
│   └── vendor/               # Hardened Redis and socket-proxy base images
├── dashboard/                # Frontend dashboard (scan submission, incident review, history)
├── docs/                     # Qualification audits, smoke reports, verification manifests
├── models/
│   └── releases/
│       ├── candidate_fusion_v26/   # Production release (trust anchor: 6fe3b2e3...)
│       │   └── evidence/           # 7,082-sample holdout, reviewer attestation, REVIEW_DECISIONS.jsonl
│       └── candidate_fusion_v27/   # Experimental challenger (428K URLs, 22K images)
├── scripts/                  # Smoke tests, OWASP audit, security scan, local deploy utilities
├── smoke_test_suite.py       # 16-point live end-to-end qualification test suite
└── docker-compose.yml        # 13-container orchestration with models and shadow profiles
```

---

## 8. Running Model Training (v27 Scale Experiments)

The v27 challenger models are pre-trained and staged. To retrain from scratch:

```bash
# URL model — 428,222 URL dataset (PhiLegit-100K + URL-Phish v2 + UCI PhiUSIIL)
cd /path/to/parent
python lightgbm_dataset/train_all_428k_urls.py

# Visual model — 22,753 screenshot embeddings (Phish360 + Zenodo + PhishingEval)
python mobileclip-dataset/train_22k_visual_model.py
```

Training produces artifacts in `lightgbm_dataset/v27_all_urls_scaled/` and `mobileclip-dataset/artifacts/visual_v27_20k_scaled/`.

> **Important:** v27 model artifacts are staged in `models/releases/candidate_fusion_v27/` with `status: experimental_challenger`. They are NOT loaded by the production runtime. The live trust anchor `6fe3b2e3...` binds exclusively to `candidate_fusion_v26`.

---

## 9. Changelog

### v27 Experimental Challenger (Oct 31, 2026)
- **428,222 URL training scale** (42× increase from v26 baseline): 18-feature PaaS signal contract (Vercel, Supabase, Cloudflare Workers); Validation ROC-AUC 0.9746
- **22,753 visual screenshot training scale** (23× increase): Test ROC-AUC 0.9232 (+7.4%), Recall 87.3% (+14.4%)
- Added `EXPERIMENTAL_DESIGNATION.md` and `experimental_evaluation.json` for full audit traceability
- Designated `experimental_challenger`; v26 production trust anchor unchanged

### v26 Production Governance (Oct 30–31, 2026)
- Fixed release-version mismatch: root `models/releases/` now synchronized to `candidate_fusion_v26`
- Fixed `MODEL_RELEASE_HOST_DIR` in `.env` to point directly to `candidate_fusion_v26`
- Consolidated reviewer attestation files into `evidence/` with SHA-256 bindings in `REVIEWER_EVIDENCE_BINDINGS.json`
- Corrected `REVIEWER_ATTESTATION.md` version header from v25 to v26
- Created `evidence_blobs` → `blobs` junction to resolve independent_evidence path references
- Training exclusion verification: pyarrow-verified, 0 overlaps, `status: verified`
- All Oct 31 workflow reports refreshed and committed to `docs/`

### v26 Production Release (Oct 29, 2026)
- First fully qualified multimodal release under `scythe_fusion_v2` contract
- 0 blockers in `model_release_readiness.py` with trust anchor `6fe3b2e3...`
- 16/16 smoke test checks PASSED on live IP-hosted phishing and benign sites

---

*SCYTHE: Automated threat heuristics, resilient defenses, zero trust by design.*
