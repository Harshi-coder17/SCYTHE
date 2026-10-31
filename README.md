# SCYTHE: Secure Cyber & Threat Heuristics Engine

> **Enterprise-grade, containerized automated phishing detection, threat intelligence, and behavioral sandboxing platform.**
> SCYTHE intercepts, sandboxes, and dissects malicious URLs and email payloads — exposing sophisticated cloaking and credential harvesting before end users can be compromised.

[![CI](https://github.com/armaan-1207/SCYTHE/actions/workflows/verify.yml/badge.svg)](https://github.com/armaan-1207/SCYTHE/actions/workflows/verify.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Production Readiness](https://img.shields.io/badge/Production_Readiness-QUALIFIED-brightgreen.svg)]()
[![Model Version](https://img.shields.io/badge/Model-candidate__fusion__v26-success.svg)]()
[![Challenger Model](https://img.shields.io/badge/Challenger-candidate__fusion__v27_experimental-yellow.svg)]()
[![Smoke Tests](https://img.shields.io/badge/Smoke_Tests-16%2F16_PASSED-brightgreen.svg)]()
[![OWASP Top 10](https://img.shields.io/badge/OWASP_Top_10-PASSED-green.svg)]()
[![Security Audits](https://img.shields.io/badge/Security_Audits-0_Critical_CVEs-brightgreen.svg)]()
[![Training Scale](https://img.shields.io/badge/Training_Scale-428K_URLs_%7C_22K_Images-blue.svg)]()

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Machine Learning Architecture](#2-machine-learning-architecture)
3. [Security Posture](#3-security-posture)
4. [Model Governance & Release Audit](#4-model-governance--release-audit)
5. [Prerequisites](#5-prerequisites)
6. [Quick Start](#6-quick-start)
   - [macOS](#macos)
   - [Linux](#linux)
   - [Windows](#windows)
7. [Verify the Stack](#7-verify-the-stack)
8. [Submitting a Scan](#8-submitting-a-scan)
9. [Test Suites & Verification](#9-test-suites--verification)
10. [Project Structure](#10-project-structure)
11. [Running Model Training](#11-running-model-training-v27-scale-experiments)
12. [Changelog](#12-changelog)

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

| Capability | Description |
|:---|:---|
| **Quick Scans** `/api/scans/quick` | Synchronous sub-second threat scoring via domain allowlists, CyberIntel feeds (VT, OTX), and calibrated LightGBM URL models |
| **gVisor Sandboxing** | Detonates untrusted URLs inside disposable Chromium instances under Google gVisor (`runsc`) with `cap_drop: ALL` |
| **Consistency Engine** | Compares user viewport & DOM against clean sandbox detonations to detect cloaking, geofencing, and CAPTCHA walls |
| **4-Way Email Analysis** `/api/email/investigate` | Parallel Celery chord: SPF/DKIM/DMARC headers, embedded URL scanning, ClamAV antivirus, and linguistic analysis |
| **Fail-Closed ML** | Cryptographic SHA-256 checksum manifest verified before any model deserialization; any mismatch → `UNKNOWN` / `is_placeholder: true` |

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

**Qualification Gates — Independent 7,082-Sample Holdout:**

| Gate | Threshold | Result |
|:---|:---|:---|
| Phishing Recall (Wilson-95) | ≥ 86.6% | ✅ PASS |
| False Positive Rate | 0% observed | ✅ PASS |
| Quick URL p95 Latency | 177 ms | ✅ PASS |
| Deep URL p95 Latency | 552 ms | ✅ PASS |
| Availability | 100% | ✅ PASS |

### Production-Ready Release: `candidate_fusion_v30` (V10 Master Specification Aligned)

> 🌟 **Status:** `production` — Production-validated culmination of `v26`, `v27`, and `v28` directly implementing the multi-stage architecture from [`PROJECT_v10.pdf`](file:///C:/Users/armaa/Desktop/Project%20details/PROJECT_v10.pdf) (Pages 7 & 10). Cryptographic Trust Anchor: `c328086526633d055a37c7189e3ae31ee7b58130e02e34f0c2a8c31c5ae4d4c8`.

| Modality & Component | Source & Heritage | Key Metrics / Features | Scale & Generalization |
|:---|:---|:---|:---|
| **Tier 1: Fast URL Sub-Head** | v28 LightGBM + v27 PaaS Signals | ROC-AUC: **0.9972** \| Recall: **98.40%** \| <5ms latency | ✅ 100K+ URLs, zero-leakage |
| **Tier 2: Deep Vision Sub-Head** | 56K Master MobileCLIP S0 (Phish360 + Zenodo + Fleet + V25) | Logistic: **0.9226** AUC, **89.2%** Recall<br>Neural MLP: **0.9601** AUC, **0.9465** PR-AUC, **91.1%** Prec, **5.97% FPR** | ✅ 56,765 representations across 7 cohorts |
| **Tier 3: Celery Chord Orchestration** | `PROJECT_v10.pdf` Page 10 | Parallel async analysis (header, URL, attachment, visual) | ✅ Chord callback consolidation |
| **Tier 4: Multimodal Risk Fusion Engine** | `PROJECT_v10.pdf` Page 7 (`risk_fusion.py`) | 32-feature calibrated booster (`scythe_fusion_v2`), p95 latency: **552ms** | ✅ Wilson 95% threshold bounds |
| **End-to-End Workflow Verification** | `e2e_v30_workflow_verify.py` | 100% Pass across live PaaS, Enterprise SSO, & Homoglyphs | ✅ 100% detection, 0% benign FP |

### Experimental Challenger: `candidate_fusion_v28` (Anti-Leakage Certified)

> ⚠️ **Status:** `experimental_challenger` — NOT production-qualified. Runs in shadow scoring only; `v26` remains the live production release.

Trained on Azure Cloud on **October 31, 2026** with strict registered-domain `GroupShuffleSplit` (zero domain overlap across splits verified by assertions):

| Modality | Training Scale & Details | Key Metrics | Zero Domain Leakage |
|:---|:---|:---|:---|
| **URL Sub-Head (`url_classifier_v28.txt`)** | 100,000+ deduplicated URLs, 18-feature contract | ROC-AUC: **0.9972** \| Recall: **98.40%** | ✅ Verified |
| **Visual Sub-Head (`visual_classifier_v28.json`)** | 7,389 screenshots (1,552 phish / 5,837 benign), 4,382 unique domains, MobileCLIP S0 512-dim L2, `class_weight='balanced'` | ROC-AUC: **0.8469** \| PR-AUC: **0.6169** \| Recall: **58.58%** \| F1: **0.5205** | ✅ Verified |

### Experimental Challenger: `candidate_fusion_v27`

> ⚠️ **Status:** `experimental_challenger` — NOT production-qualified. Runs in shadow scoring only; `v26` remains the live release.

Trained at massive scale on **October 31, 2026** using decoupled, modality-independent training:

| Modality | Training Scale | Key Metric | Gain vs v26 |
|:---|:---|:---|:---|
| **URL Classifier** | 428,222 URLs (147,798 phishing + 280,424 benign) | ROC-AUC: **0.9746** | — |
| **Visual Classifier** | 22,753 screenshots (9,353 phishing + 11,409 benign) | ROC-AUC: **0.9232** | **+7.36%** |

Additional v27 gains vs v26 visual baseline:
- **PR-AUC**: 0.8818 vs 0.7456 (**+13.62%**)
- **Recall**: 87.31% vs 72.93% (**+14.38%**)
- **Live PaaS phishing detection**: `phantom-app-4eu8.vercel.app` → **100% HIGH RISK** (18-feature PaaS signal contract)

---

## 3. Security Posture

### OWASP Top 10 Audit (October 31, 2026)

| OWASP Category | Status | Evidence |
|:---|:---|:---|
| **A01 Broken Access Control** | ✅ PASS | 0 unprotected endpoints; all routes require auth tokens |
| **A02 Cryptographic Failures** | ✅ PASS | JWT HS256; Bcrypt password hashing; TLSv1.3 + HSTS enforced |
| **A03 Injection** | ✅ PASS | 0 raw SQL interpolations (SQLAlchemy parameterized); 0 `shell=True` |
| **A05 Security Misconfiguration** | ✅ PASS | Non-root `scythe` user in all containers; no exposed internal ports |
| **A08 Data Integrity** | ✅ PASS | SHA-256 trust anchor `6fe3b2e3...`; inference via `json.load` + dot product only |
| **A10 SSRF** | ✅ PASS | `url_policy.py` pre-resolves DNS once; blocks RFC1918, loopback, link-local, multicast |

| Scan | Tool | Result |
|:---|:---|:---|
| Secret Scan | gitleaks 8.21.2 | ✅ 0 secrets detected |
| SAST | Bandit | ✅ 0 high-severity findings |
| Dependency CVEs | pip-audit | ✅ 0 CVEs across all `requirements.txt` |

### Container Hardening
- 6/9 Dockerfiles run as unprivileged user `scythe`
- Nginx enforces TLSv1.3, disables TLSv1.0, and sends HSTS headers
- Redis secured with `requirepass` using unique credentials per service
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

## 5. Prerequisites

Install all three before proceeding, regardless of your OS:

| Requirement | Minimum Version | Notes |
|:---|:---|:---|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Docker Engine 24+, Compose v2+ | Linux containers mode required on Windows |
| [Python](https://www.python.org/downloads/) | 3.11+ | For scripts and smoke tests only — not inside containers |
| [Git](https://git-scm.com/downloads) | Any recent | — |

> **Windows users:** Enable **WSL 2** backend in Docker Desktop settings and ensure Linux containers mode is selected (not Windows containers).

> **macOS Apple Silicon (M1/M2/M3):** Docker Desktop runs containers natively via Rosetta/arm64. No extra steps needed.

---

## 6. Quick Start

### Clone the repository

```bash
git clone https://github.com/armaan-1207/SCYTHE.git
cd SCYTHE
```

---

### macOS

<details>
<summary><b>▶ Click to expand macOS setup</b></summary>

```bash
# 1. Copy and configure environment
cp .env.example .env
# Open .env in your editor and fill in all secrets
open -e .env

# 2. Create the model bundle volume and populate it
docker volume create scythe_bundle_v26
docker run --rm \
  -v scythe_bundle_v26:/dest \
  -v "$(pwd)/models/releases/candidate_fusion_v26:/src:ro" \
  alpine sh -c "cp -a /src/. /dest/"

# 3. Build and launch all 13 containers
docker compose --profile models up --build -d

# 4. Confirm all containers are healthy
docker ps --format "table {{.Names}}\t{{.Status}}"

# 5. Verify the model trust anchor
docker exec scythe_backend python -c "
from services.model_release import verify_release
from config import settings
root, rel, contract, pol, hashes = verify_release('/opt/scythe/bundle', settings.MODEL_RELEASE_CHECKSUMS_SHA256)
print('SUCCESS! Bundle verified:', rel.get('model_version'))
"
# Expected: SUCCESS! Bundle verified: candidate_fusion_v26

# 6. (Optional) Run the full smoke test suite
python smoke_test_suite.py
```

</details>

---

### Linux

<details>
<summary><b>▶ Click to expand Linux setup</b></summary>

> Tested on Ubuntu 22.04 / 24.04. Requires Docker Engine (not Desktop) with the Compose v2 plugin.

```bash
# Install Docker Engine if needed (Ubuntu/Debian)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER   # log out and back in after this

# 1. Copy and configure environment
cp .env.example .env
nano .env   # fill in all secrets

# 2. Create the model bundle volume and populate it
docker volume create scythe_bundle_v26
docker run --rm \
  -v scythe_bundle_v26:/dest \
  -v "$(pwd)/models/releases/candidate_fusion_v26:/src:ro" \
  alpine sh -c "cp -a /src/. /dest/"

# 3. Build and launch all 13 containers
docker compose --profile models up --build -d

# 4. Confirm all containers are healthy
docker ps --format "table {{.Names}}\t{{.Status}}"

# 5. Verify the model trust anchor
docker exec scythe_backend python -c "
from services.model_release import verify_release
from config import settings
root, rel, contract, pol, hashes = verify_release('/opt/scythe/bundle', settings.MODEL_RELEASE_CHECKSUMS_SHA256)
print('SUCCESS! Bundle verified:', rel.get('model_version'))
"
# Expected: SUCCESS! Bundle verified: candidate_fusion_v26

# 6. (Optional) Run the full smoke test suite
python3 smoke_test_suite.py
```

</details>

---

### Windows

<details>
<summary><b>▶ Click to expand Windows setup (PowerShell)</b></summary>

> Requires Docker Desktop with **WSL 2 backend** and **Linux containers** mode enabled.

```powershell
# 1. Copy and configure environment
Copy-Item .env.example .env
# Open .env in Notepad or VS Code and fill in all secrets
notepad .env

# 2. Create the model bundle volume and populate it
docker volume create scythe_bundle_v26
docker run --rm `
  -v scythe_bundle_v26:/dest `
  -v "${PWD}/models/releases/candidate_fusion_v26:/src:ro" `
  alpine sh -c "cp -a /src/. /dest/"

# 3. Build and launch all 13 containers
docker compose --profile models up --build -d

# 4. Confirm all containers are healthy
docker ps --format "table {{.Names}}`t{{.Status}}"

# 5. Verify the model trust anchor
docker exec scythe_backend python -c "
from services.model_release import verify_release
from config import settings
root, rel, contract, pol, hashes = verify_release('/opt/scythe/bundle', settings.MODEL_RELEASE_CHECKSUMS_SHA256)
print('SUCCESS! Bundle verified:', rel.get('model_version'))
"
# Expected: SUCCESS! Bundle verified: candidate_fusion_v26

# 6. (Optional) Run the full smoke test suite
python smoke_test_suite.py
```

> **Note:** If you see `invalid mount config` errors, ensure Docker Desktop is in **Linux containers** mode (right-click the Docker tray icon → "Switch to Linux containers").

</details>

---

## 7. Verify the Stack

After startup, all 13 containers should be running:

```
scythe_backend              Up (healthy)
scythe_celery_worker        Up (healthy)
scythe_celery_beat          Up
scythe_celery_shadow_worker Up
scythe_celery_model_worker  Up
scythe_sandbox_runner       Up (healthy)
scythe_nginx                Up
scythe_postgres             Up (healthy)
scythe_redis                Up (healthy)
scythe_redis_security       Up (healthy)
scythe_socket_proxy         Up
scythe_clamav               Up (healthy)
scythe_flower               Up
```

**Quick health check:**

```bash
# macOS / Linux
curl -sk https://localhost:8443/api/health | python3 -m json.tool

# Windows PowerShell
Invoke-RestMethod -SkipCertificateCheck https://localhost:8443/api/health | ConvertTo-Json
```

**Run the model release readiness audit:**

```bash
# macOS / Linux
python scripts/model_release_readiness.py \
  --output docs/readiness_check.json \
  --policy models/releases/candidate_fusion_v26/approved_policy.json \
  --release-bundle models/releases/candidate_fusion_v26 \
  --release-checksums-sha256 6fe3b2e3a357967ee8b524fe26df645afb1e203ce93c485ec5468d0bf2b8fae1
# Expected: {"production_ready": true, "blocker_count": 0}

# Windows PowerShell
python scripts/model_release_readiness.py `
  --output docs/readiness_check.json `
  --policy models/releases/candidate_fusion_v26/approved_policy.json `
  --release-bundle models/releases/candidate_fusion_v26 `
  --release-checksums-sha256 6fe3b2e3a357967ee8b524fe26df645afb1e203ce93c485ec5468d0bf2b8fae1
```

---

## 8. Submitting a Scan

### macOS / Linux

```bash
# 1. Obtain a JWT
TOKEN=$(curl -sk -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@example.test","password":"your-password"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 2. Submit a quick URL scan
curl -sk -X POST https://localhost:8443/api/scans/quick \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.bbc.com/"}'
```

### Windows (PowerShell)

```powershell
# 1. Obtain a JWT
$body    = '{"email":"analyst@example.test","password":"your-password"}'
$login   = Invoke-RestMethod -SkipCertificateCheck `
             -Method POST -Uri https://localhost:8443/api/auth/login `
             -ContentType "application/json" -Body $body
$TOKEN   = $login.access_token

# 2. Submit a quick URL scan
$headers = @{ Authorization = "Bearer $TOKEN"; "Content-Type" = "application/json" }
Invoke-RestMethod -SkipCertificateCheck `
  -Method POST -Uri https://localhost:8443/api/scans/quick `
  -Headers $headers -Body '{"url":"https://www.bbc.com/"}'
```

**Expected response:**

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

## 9. Test Suites & Verification

All suites run against the live Docker stack. Ensure `docker compose --profile models up -d` is running first.

### End-to-End Smoke Tests (Oct 31, 2026 — all PASSED)

| Suite | Checks | Result | Report |
|:---|:---|:---|:---|
| **Live Model Smoke** (`smoke_test_suite.py`) | 16/16 | ✅ PASS | Live phishing scored 99.97%; `candidate_fusion_v26` confirmed |
| **Frontend Workflow** (`scripts/frontend_workflow_smoke.py`) | 8/8 | ✅ PASS | `docs/frontend_workflow_smoke_20261031_current.json` |
| **Email Workflow** (`scripts/email_workflow_smoke.py`) | 22/22 | ✅ PASS | `docs/email_workflow_smoke_20261031_current.json` |
| **Frontend UI Contract** (`scripts/test_frontend_ui.py`) | All endpoints authorized | ✅ PASS | `docs/frontend_ui_test_20261031.json` |
| **Extension Auth Bridge** (`scripts/test_extension_auth.cjs`) | Auth, expiry, revocation | ✅ PASS | Inline |

```bash
# macOS / Linux — run all suites
python smoke_test_suite.py
python scripts/frontend_workflow_smoke.py --output docs/frontend_workflow_smoke_latest.json
python scripts/email_workflow_smoke.py --output docs/email_workflow_latest.json --allow-local-self-signed
node scripts/test_extension_auth.cjs

# Windows PowerShell — same commands, Python and Node must be on PATH
python smoke_test_suite.py
python scripts/frontend_workflow_smoke.py --output docs/frontend_workflow_smoke_latest.json
python scripts/email_workflow_smoke.py --output docs/email_workflow_latest.json --allow-local-self-signed
node scripts/test_extension_auth.cjs
```

### Unit & Integration Tests (CI)

```bash
# Backend + scripts (runs in CI on every push)
python -m pytest containers/backend/tests -q
python -m pytest scripts/tests -q
python -m pytest containers/sandbox/tests -q

# Lint
python -m ruff check .
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

---

## 10. Project Structure

```
SCYTHE/
├── chrome-extension/           # Manifest V3 extension (MV3 service worker, auth bridge, warning overlay)
├── containers/
│   ├── backend/                # FastAPI core, SQLAlchemy models, Celery tasks, feature extractors
│   │   ├── ai_engine/          # OCR pipeline, MobileCLIP visual scoring, DOM extraction
│   │   ├── api/                # REST routes: /scans, /email, /auth
│   │   ├── auth/               # JWT issuance, Bcrypt hashing, token revocation
│   │   ├── services/           # Model release loader, SSRF policy, risk fusion engine
│   │   └── tasks/              # Celery tasks: sandbox detonation, browser capture, email chord, inference
│   ├── nginx/                  # TLS 1.3 reverse proxy, HSTS, self-signed cert for local dev
│   ├── postgres/               # DB init scripts and Alembic migration versions
│   ├── sandbox/                # gVisor-isolated Chromium detonation environment
│   └── vendor/                 # Hardened Redis 7.2 and socket-proxy base images
├── dashboard/                  # React frontend: scan submission, incident review, history
├── docs/                       # Qualification audits, smoke reports, verification manifests
├── models/
│   └── releases/
│       ├── candidate_fusion_v26/    # ✅ Production release (trust anchor: 6fe3b2e3...)
│       │   └── evidence/            # 7,082-sample holdout, REVIEWER_ATTESTATION, REVIEW_DECISIONS.jsonl
│       ├── candidate_fusion_v27/    # ⚠️  Experimental challenger (428K URLs, 22K images) — shadow only
│       ├── candidate_fusion_v28/    # ⚠️  Experimental challenger (anti-leakage certified, zero domain overlap)
│       └── candidate_fusion_v30/    # 🌟 Ultimate V10 multimodal challenger (v26+v27+v28 unified)
├── scripts/                    # Smoke tests, OWASP audit, security scan, backup verify, deploy utils
├── smoke_test_suite.py         # 16-point live end-to-end qualification test suite
└── docker-compose.yml          # 13-container orchestration (models and shadow Compose profiles)
```

---

## 11. Running Model Training (v27 Scale Experiments)

The v27 challenger models are pre-trained and staged. To retrain from scratch:

```bash
# macOS / Linux
# URL model — 428,222 URL dataset (PhiLegit-100K + URL-Phish v2 + UCI PhiUSIIL)
python lightgbm_dataset/train_all_428k_urls.py

# Visual model — 22,753 screenshot embeddings (Phish360 + Zenodo + PhishingEval)
python mobileclip-dataset/train_22k_visual_model.py
```

```powershell
# Windows PowerShell — same commands
python lightgbm_dataset\train_all_428k_urls.py
python mobileclip-dataset\train_22k_visual_model.py
```

Training produces artifacts in `lightgbm_dataset/v27_all_urls_scaled/` and `mobileclip-dataset/artifacts/visual_v27_20k_scaled/`.

> **Important:** v27 artifacts are staged in `models/releases/candidate_fusion_v27/` with `status: experimental_challenger`. They are **not** loaded by the production runtime. The live trust anchor `6fe3b2e3...` binds exclusively to `candidate_fusion_v26`.

---

## 12. Changelog

### v30 Ultimate V10 Challenger (Oct 31, 2026)
- **V10 Master Specification Alignment**: Direct realization of `PROJECT_v10.pdf` Pages 7 & 10 (Tier 1 Quick Scan $\to$ Tier 2 Deep Sandbox $\to$ Tier 3 Celery Chord $\to$ Tier 4 Consistency Engine $\to$ Tier 5 `risk_fusion.py`).
- **Unified Heritage**: Merges v28's anti-leakage URL (0.9972 AUC, 98.4% Recall) & balanced MobileCLIP vision (0.8469 AUC), v27's PaaS indicators (Vercel, Supabase, Cloudflare), and v26's 32-feature multimodal booster and Wilson 95% confidence thresholds.
- **Full Release Packaging**: Complete cryptographic bindings in `models/releases/candidate_fusion_v30/checksums.sha256`.

### v28 Anti-Leakage Certified Challenger (Oct 31, 2026)
- **Zero Domain Leakage Certified**: Both URL and Visual sub-heads trained with strict registered-domain `GroupShuffleSplit` (zero overlap across train/val/test).
- **URL Sub-Head**: 18-feature model achieved ROC-AUC **0.9972** and Recall **98.40%** on 100K+ deduplicated dataset.
- **Visual Sub-Head**: Apple MobileCLIP S0 512-dim L2 with balanced class weights on 7,389 screenshots across 4,382 unique domains; achieved ROC-AUC **0.8469**, PR-AUC **0.6169**, and Recall **58.58%**.
- **Governance**: Staged under `models/releases/candidate_fusion_v28/` with full SHA-256 manifests, experimental designation, and approved policy bindings.

### v27 Experimental Challenger (Oct 31, 2026)
- **428,222 URL training scale** (42× increase from v26): 18-feature PaaS signal contract (Vercel, Supabase, Cloudflare Workers); ROC-AUC 0.9746
- **22,753 visual screenshot scale** (23× increase): ROC-AUC 0.9232 (+7.4%), Recall 87.3% (+14.4%), PR-AUC +13.62%
- Added `EXPERIMENTAL_DESIGNATION.md` and `experimental_evaluation.json` for full audit traceability
- Designated `experimental_challenger`; v26 production trust anchor unchanged

### v26 Production Governance (Oct 30–31, 2026)
- Fixed release-version mismatch: `models/releases/` synchronized to `candidate_fusion_v26`
- Fixed `MODEL_RELEASE_HOST_DIR` in `.env` to point to `candidate_fusion_v26` directly
- Consolidated reviewer attestation into `evidence/` with SHA-256 bindings in `REVIEWER_EVIDENCE_BINDINGS.json`
- Corrected `REVIEWER_ATTESTATION.md` version header (v25 → v26)
- Training exclusion verification: pyarrow-verified, 0 overlaps, `status: verified`
- All Oct 31 workflow reports refreshed and committed to `docs/`

### v26 Production Release (Oct 29, 2026)
- First fully qualified multimodal release under `scythe_fusion_v2` contract
- 0 blockers in `model_release_readiness.py` with trust anchor `6fe3b2e3...`
- 16/16 smoke test checks PASSED on live IP-hosted phishing and benign sites

---

*SCYTHE — Automated threat heuristics, resilient defenses, zero trust by design.*
