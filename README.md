# SCYTHE — Secure Cyber & Threat Heuristics Engine

> **Containerized, multimodal phishing detection, behavioral sandboxing, and threat intelligence platform.**  
> SCYTHE intercepts, detonates, and analyzes malicious URLs, web pages, and email payloads — neutralizing zero-hour evasions, PaaS abuse, and visual brand impersonation before end users are compromised.

[![CI](https://github.com/armaan-1207/SCYTHE/actions/workflows/verify.yml/badge.svg)](https://github.com/armaan-1207/SCYTHE/actions/workflows/verify.yml)
[![Tests](https://img.shields.io/badge/Tests-491%20Passed%20%7C%200%20Failed-brightgreen.svg)]()
[![Model](https://img.shields.io/badge/Production%20Model-candidate__fusion__v30-brightgreen.svg)]()
[![Holdout AUC](https://img.shields.io/badge/Holdout%20ROC--AUC-0.9906-blue.svg)]()
[![FPR](https://img.shields.io/badge/False%20Positive%20Rate-0.27%25-success.svg)]()
[![Security](https://img.shields.io/badge/Security-0%20Leaks%20%7C%200%20SAST-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

## Table of Contents

1. [What Makes SCYTHE Different?](#1-what-makes-scythe-different)
2. [The 5-Tier Detection Pipeline](#2-the-5-tier-detection-pipeline)
3. [Machine Learning Models & Benchmarks](#3-machine-learning-models--benchmarks)
4. [Security & Hardening Posture](#4-security--hardening-posture)
5. [Container Infrastructure](#5-container-infrastructure)
6. [Installation & Setup](#6-installation--setup)
   - [Prerequisites](#prerequisites)
   - [Windows](#windows)
   - [macOS](#macos)
   - [Linux](#linux)
7. [Chrome Extension (Manifest V3)](#7-chrome-extension-manifest-v3)
8. [API Reference](#8-api-reference)
9. [Verification & Test Suites](#9-verification--test-suites)
10. [Repository Structure](#10-repository-structure)

---

## 1. What Makes SCYTHE Different?

Most phishing detectors rely on static blocklists (Google Safe Browsing, PhishTank) or simple lexical URL regexes. Modern attackers bypass these trivially with ephemeral domains, bulletproof hosting, and brand cloaking.

SCYTHE introduces an **air-gapped, multimodal behavioral architecture** that solves the fundamental flaws of legacy security gateways:

```
┌─────────────────────────────────────────┬─────────────────────────────────────────┐
│  Legacy Security Gateways               │  SCYTHE Multimodal Platform             │
├─────────────────────────────────────────┼─────────────────────────────────────────┤
│ ❌ Stale feeds (hours to days)          │ ⚡ Real-time inline inference (<6ms)     │
│ ❌ Blind to visual brand impersonation  │ 👁️ MobileCLIP S0 512-dim neural vision  │
│ ❌ Fooled by cloaking & geofencing      │ 🛡️ Dynamic gVisor anti-cloaking sandbox │
│ ❌ Fails on PaaS hosts (Vercel, Pages)  │ ☁️ 18-feature PaaS & entropy heuristics │
│ ❌ Flags legitimate enterprise SSO      │ 🎯 Consistency Engine: 0% SSO false pos  │
│ ❌ Vulnerable to pickle model poisoning │ 🔒 Sealed SHA-256 cryptographic anchors  │
└─────────────────────────────────────────┴─────────────────────────────────────────┘
```

### Key Differentiators

#### 1. Solving the Enterprise SSO False Positive Problem
Legacy scanners flag `login.microsoftonline.com`, `accounts.google.com`, and `github.com/login` as phishing because they contain keywords like `login`, `oauth`, and `account`.

**SCYTHE's solution**: The Stage 4 **Consistency Engine** cross-validates visual brand elements against DNS hostnames, SSL Certificate Authorities, and Subject Alternative Names (SANs). Real Microsoft and Google logins pass with **0% false positives**; impostors hosted on free PaaS platforms are immediately blocked.

#### 2. True Multimodal Fusion — Not Isolated Heuristics
Phishing cannot be solved by URL analysis or computer vision alone. SCYTHE fuses **5 distinct tiers** of evidence:
1. **Lexical & Structural URL features** — 18 signals including Shannon entropy, bogon IP, and PaaS subdomain checks.
2. **Dynamic Browser Detonation** — isolated gVisor-hardened Chromium sandbox.
3. **Computer Vision Head** — MobileCLIP S0 512-dimensional visual embeddings.
4. **Consistency Cross-Checking** — geofencing detection, CAPTCHA walls, and DOM-vs-SSL mismatch analysis.
5. **Calibrated Risk Fusion** — Wilson 95% statistical confidence intervals for actionable verdicts.

#### 3. Immune to Evasion & Cloaking
Attackers frequently serve a clean 200 OK page to security scanners while redirecting human victims to phishing forms. SCYTHE's sandbox records complete **HAR network activity**, dynamic DOM mutations, and passive screenshots, analyzing JavaScript redirect loops, canvas manipulation, and client-side cloaking in real time.

#### 4. Cryptographic Model Governance — Zero Pickle Risk
Traditional ML platforms expose pipelines to model poisoning via unsafe pickle deserialization.

**SCYTHE's rule**: No model is ever loaded without matching its pre-computed SHA-256 cryptographic trust anchor. If any weight, contract, or evaluation file deviates by a single bit, the platform **fails closed** (`UNKNOWN`) without executing hostile code.

#### 5. Extreme Throughput at Negligible Latency
- **Feature extraction**: ~106.7 µs per URL.
- **LightGBM inference**: ~2.71 µs per URL (369,000+ URLs/second).
- **End-to-end URL pipeline**: ~110.3 µs (~9,000+ full analyses/second) — transparent inline proxying with zero user-perceivable delay.

---

## 2. The 5-Tier Detection Pipeline

```
                      [ Chrome Extension (MV3) ]
                                  │
                     [ Nginx TLS 1.3 Proxy (:8443) ]
                                  │
                    [ FastAPI Backend Core (:8000) ]
                                  │
      ┌───────────────────────────┴───────────────────────────┐
      ▼                                                       ▼
[ Tier 1: Quick Scan ]                           [ Tier 2: Deep Detonation ]
• Domain Allowlist Engine                        • gVisor Chromium Sandbox
• 18-Feature LightGBM Classifier                 • Full HAR & DOM Extraction
• Latency: <5ms                                  • MobileCLIP S0 512-dim Vision
      │                                                       │
      └───────────────────────────┬───────────────────────────┘
                                  ▼
                    [ Tier 3: Celery Chord Fan-Out ]
               Async Orchestrator — URL / File / Vision Workers
                                  │
                                  ▼
                   [ Tier 4: Multimodal Consistency Engine ]
                Cross-Validates DOM vs. SSL vs. Brand vs. Hostname
                                  │
                                  ▼
                     [ Tier 5: Risk Fusion Engine ]
         32-Feature Calibrated Booster (scythe_fusion_v2)
                                  │
                                  ▼
           [ Verdict: SAFE / LOW / MEDIUM / HIGH (Wilson 95% CI) ]
```

| Tier | Endpoint | Function |
|:-----|:---------|:---------|
| **1 — Quick Scan** | `POST /api/scans/quick` | Sub-5ms lexical + LightGBM classifier |
| **2 — Sandbox Detonation** | `POST /api/scans/url` | gVisor Chromium + HAR + screenshots |
| **3 — Async Fan-Out** | Internal Celery | URL enrichment, file parsing, ClamAV, vision |
| **4 — Consistency Engine** | Internal | Brand vs. TLS vs. DNS cross-validation |
| **5 — Risk Fusion** | Internal | 32-feature calibrated ensemble verdict |

---

## 3. Machine Learning Models & Benchmarks

SCYTHE's models represent a deliberate evolution across **428,000+ historical URLs** and **80,000+ screenshots**:

### 5,000+ Real-World URL Holdout Benchmark

Production model `candidate_fusion_v30` was evaluated on two untouched holdout partitions — a balanced benchmark and the full prospective validation set:

| Benchmark | URLs Evaluated | ROC-AUC | Accuracy | Recall | Precision | False Positive Rate | Latency |
|:----------|:---------------|:--------|:---------|:-------|:----------|:--------------------|:--------|
| **Balanced Benchmark** | 5,000 (2,500 ÷ 2,500) | **0.9908** | **98.04%** | **96.32%** | **99.75%** | **0.24%** (6 / 2,500) | 110.3 µs |
| **Full Holdout Partition** | 21,997 (17,378 benign / 4,619 phish) | **0.9906** | **98.97%** | **96.10%** | **98.95%** | **0.27%** (47 / 17,378) | 110.3 µs |

```
Confusion Matrix — Balanced 5,000 URLs:
  TN: 2,494   FP:     6    (Actual Benign:   2,500)
  FN:    92   TP: 2,408    (Actual Phishing: 2,500)

Confusion Matrix — Full 21,997-URL Holdout:
  TN: 17,331   FP:    47   (Actual Benign:   17,378)
  FN:   180    TP: 4,439   (Actual Phishing:  4,619)
```

### Model Evolution: v1 → v27 → v30

| Metric | v1 — Early Baseline | v27 — Scale Experiment | **v30 — Active Production** |
|:-------|:--------------------|:----------------------|:---------------------------|
| **Feature Contract** | 15 features | 18 features (PaaS added) | **18 features (Contract v2)** |
| **Booster Trees** | 100 trees | 500 trees | **250 calibrated trees** |
| **URL Training Corpus** | ~50k historical | 428,222 URLs | **87,204 prospective (from 109k cohort)** |
| **Validation ROC-AUC** | ~0.94 (est.) | 0.9747 | **0.9972** |
| **Holdout ROC-AUC** | — | 0.8654 | **0.9906** |
| **Precision** | ~85% (est.) | 81.20% | **98.77%** |
| **Recall** | ~88% (est.) | 89.28% | **96.08%** |
| **False Positive Rate** | ~3.2% (est.) | 5.46% (deep tree overfit) | **0.27% (gate ≤ 1.0%)** |
| **Inference Latency** | ~5.8 µs | 6.6 µs | **2.71 µs** |
| **PaaS Threat Detection** | None | Partial | **100% (Vercel, Pages, Firebase)** |
| **Production Status** | Deprecated | Archived Reference | **Sealed Active Production** |

> **Note**: v1 metrics are estimates — no v1 model artifact is retained in the repository. v27 and v30 figures are sourced from verified experimental evaluation manifests.

### Visual Classification Head

The MobileCLIP S0 visual classifier was trained on **56,765 representations** (48,574 train / 1,991 test, GroupShuffleSplit by registered domain — zero cross-split leakage):

| Head | Test ROC-AUC | Test PR-AUC | Precision | Recall | F1 |
|:-----|:------------|:------------|:----------|:-------|:---|
| Logistic Regression | 0.9267 | 0.8859 | 79.50% | 88.90% | 0.8394 |
| Neural MLP (active) | 0.9585 | 0.9399 | 90.00% | 87.20% | 0.8856 |

---

## 4. Security & Hardening Posture

| Check | Result |
|:------|:-------|
| **Gitleaks Secret Audit** | ✅ PASS — 0 credentials or tokens in repository history |
| **Bandit SAST** | ✅ PASS — 0 high/medium findings across all Python services |
| **pip-audit Dependency Scan** | ✅ PASS — 0 known CVEs in locked dependencies |
| **OWASP SSRF Protection** | `ssrf_guard.py` — single DNS pre-resolution, blocks RFC1918 & link-local metadata (`169.254.169.254`) |
| **Authentication** | Argon2/Bcrypt hashing, HIBP compromised-password checks, JWT HS256 + Redis atomic revocation |
| **Container Hardening** | Unprivileged `scythe` (UID 10001), `cap_drop: [ALL]`, read-only root filesystems |
| **Image Vulnerability Gate** | Trivy scan gate on all 8 application images (CI `compose-browser-workflow`) |

---

## 5. Container Infrastructure

SCYTHE runs as a 13-container microservices mesh via Docker Compose:

```
Port 8443 (HTTPS) / Port 8080 (HTTP)
  │
  scythe_nginx              — TLS 1.3 reverse proxy, CSP headers, rate limiting
  ├── scythe_backend        — FastAPI REST & WebSocket gateway
  ├── scythe_postgres       — PostgreSQL 16 relational store
  ├── scythe_redis          — Celery broker & result cache
  ├── scythe_redis_security — JWT revocation blacklist
  ├── scythe_clamav         — ClamAV daemon stream scanner
  ├── scythe_celery_worker      — Core task pipeline
  ├── scythe_celery_beat        — Periodic health sweeper
  ├── scythe_celery_model_worker — Production ML inference queue
  ├── scythe_celery_shadow_worker — Shadow verification queue
  ├── scythe_socket_proxy   — Hardened Docker socket proxy
  ├── scythe_sandbox_runner — Playwright Chromium execution engine
  └── scythe_sandbox_net_holder — Isolated bridge network holder
```

---

## 6. Installation & Setup

### Prerequisites

| Requirement | Minimum |
|:------------|:--------|
| Docker Engine | 24.x + Docker Compose v2 |
| Python | 3.11+ |
| RAM | 6 GB |
| Disk | 10 GB |

---

### Windows

> Requires Docker Desktop with the WSL2 backend enabled.

```powershell
# 1. Clone the repository
git clone https://github.com/armaan-1207/SCYTHE.git
cd SCYTHE

# 2. Create the environment file
Copy-Item .env.production.example .env
# Edit .env to set your secrets before proceeding

# 3. Set up Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r containers/backend/requirements.txt
playwright install chromium

# 4. Start the 13-container fleet
docker compose --profile shadow --profile models up -d

# 5. Verify all containers are healthy
docker ps --format "table {{.Names}}`t{{.Status}}`t{{.Ports}}"

# 6. Open analyst dashboard
Start-Process "https://localhost:8443/dashboard/"
```

---

### macOS

> Requires Docker Desktop for Mac or [Colima](https://github.com/abiosoft/colima).

```bash
# 1. Clone the repository
git clone https://github.com/armaan-1207/SCYTHE.git
cd SCYTHE

# 2. Create the environment file
cp .env.production.example .env
# Edit .env to set your secrets

# 3. Set up Python virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r containers/backend/requirements.txt
playwright install chromium

# 4. Start the fleet
docker compose --profile shadow --profile models up -d

# 5. Check container status
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# 6. Open analyst dashboard
open https://localhost:8443/dashboard/
```

---

### Linux

> Tested on Ubuntu 22.04 / 24.04 LTS and Debian 12.

```bash
# 1. Install Docker Engine (if not already installed)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker

# 2. Clone the repository
git clone https://github.com/armaan-1207/SCYTHE.git
cd SCYTHE

# 3. Create the environment file
cp .env.production.example .env
# Edit .env to set your secrets

# 4. Install system dependencies
sudo apt-get install -y libpq5 libzbar0 libgl1 tesseract-ocr

# 5. Set up Python virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r containers/backend/requirements.txt
playwright install --with-deps chromium

# 6. Start the fleet
docker compose --profile shadow --profile models up -d

# 7. Verify container health
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

---

## 7. Chrome Extension (Manifest V3)

SCYTHE ships a lightweight Manifest V3 browser extension that monitors navigation, performs background threat evaluations, and displays risk badges in real time.

### Setup

**1. Configure the backend origin**

Open [`chrome-extension/config.js`](chrome-extension/config.js) and confirm:
```javascript
// Default: local Docker Compose stack exposed via Nginx TLS
const SCYTHE_ORIGIN = "https://localhost:8443";
```

**2. Load the extension**

1. Navigate to `chrome://extensions/` in Chrome, Edge, or Brave.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked**.
4. Select the `chrome-extension/` directory.
5. The **SCYTHE Threat Shield** icon appears in your toolbar.

**3. Connect to your analyst account**

1. Open `https://localhost:8443/dashboard/components/auth.html`.
2. Register or sign in.
3. Go to **Settings** → **Connect signed-in browser extension**.
4. The extension receives and stores your session token via `auth-bridge.js`.

### Features

| Feature | Description |
|:--------|:------------|
| **Auto Analysis** | `background.js` intercepts top-level navigations, calls `/api/scans/quick`, and updates the toolbar badge (`SAFE` / `WARN` / `HIGH`) |
| **Manual Deep Scan** | Click the icon to view real-time risk score and latency; trigger full gVisor sandbox detonation on demand |
| **Interstitial Warning** | Confirmed high-risk URLs redirect to `warning.html` before the page loads, blocking credential exposure |

---

## 8. API Reference

### Quick URL Scan
```bash
curl -k -X POST https://localhost:8443/api/scans/quick \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://phantom-app-4eu8.vercel.app/login"}'
```
```json
{
  "scan_id": "4a71b269-e6da-4fb1-90a6-98ecf91a5e12",
  "url": "https://phantom-app-4eu8.vercel.app/login",
  "risk_score": 99.97,
  "risk_level": "HIGH",
  "model_version": "candidate_fusion_v30",
  "is_placeholder": false,
  "is_whitelisted": false
}
```

### Deep Sandbox Detonation
```bash
curl -k -X POST https://localhost:8443/api/scans/url \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-domain.example.com"}'
```

### File & Malware Scan
```bash
curl -k -X POST https://localhost:8443/api/scans/file \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -F "file=@suspicious_payload.pdf"
```

### Email Pipeline
```bash
curl -k -X POST https://localhost:8443/api/email/analyze \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -F "file=@phishing_sample.eml"
```

---

## 9. Verification & Test Suites

SCYTHE ships 491 automated tests (100% pass rate) covering unit, security, integration, and live workflow scenarios.

### Run the Full Test Suite

```bash
# Backend, URL contract, and offline email regressions (309 tests)
PYTHONPATH=containers/backend pytest containers/backend/tests/ -q

# Deployment, security-tool, and research-gate regressions (143 tests)
pytest scripts/tests/ -q

# Sandbox SSRF, egress-proxy, and redacted HAR tests (13 tests)
pytest containers/sandbox/tests/ -q

# Research and model governance tests (26 tests)
pytest research/ -q
```

### Run the Benchmarks & Live Workflows

```bash
# 5,000-URL balanced + 21,997-URL full holdout benchmark
python scripts/test_5k_actual_urls.py

# Live end-to-end v30 pipeline verification (5 scenarios)
python scripts/e2e_v30_workflow_verify.py

# Full live email & ClamAV workflow (22 checks)
python scripts/email_workflow_smoke.py --output email-smoke.json --allow-local-self-signed

# Frontend browser workflow (login, scan, isolation, revocation)
python scripts/frontend_workflow_smoke.py --origin https://localhost:8443

# Security scans (secrets, SAST, dependency audit)
python scripts/security_scan.py --checks secrets sast deps --output security-results
```

### CI Pipeline (GitHub Actions)

The [`verify.yml`](.github/workflows/verify.yml) workflow runs on every push and pull request:

| Job | What it checks |
|:----|:---------------|
| `backend` | 309 backend + email tests, URL contract regressions |
| `sandbox` | 13 SSRF, egress-proxy, and HAR tests |
| `quality` | Actionlint, Ruff linting, Chrome extension JS syntax |
| `source-security` | Gitleaks secrets scan, Bandit SAST, pip-audit CVE check |
| `compose-browser-workflow` | Full Docker stack + Playwright browser workflow + Trivy image gate *(manual dispatch only)* |

---

## 10. Repository Structure

```text
SCYTHE/
├── .github/workflows/
│   └── verify.yml              # CI pipeline (backend, sandbox, quality, security)
├── containers/
│   ├── backend/                # FastAPI core, Celery workers, auth, models
│   │   ├── ai_engine/          # MobileCLIP S0 vision head & LightGBM inference
│   │   ├── api/                # REST endpoints (/quick, /full, /file, /email)
│   │   ├── consistency_engine/ # Brand vs. DOM vs. SSL cross-validator
│   │   ├── services/           # Feature extractors, risk fusion pipeline
│   │   └── tests/              # 309 unit, integration, and security tests
│   ├── nginx/                  # Hardened reverse proxy, TLS 1.3, rate limits
│   └── sandbox/                # Playwright detonation runner, SSRF guard
├── chrome-extension/           # Manifest V3 browser extension
│   ├── background.js           # Service worker — navigation interception
│   ├── popup.html / popup.js   # Extension popup UI
│   ├── auth-bridge.js          # Secure session token bridge
│   ├── warning.html            # Interstitial threat warning page
│   └── config.js               # Backend origin configuration
├── dashboard/                  # Static HTML/JS analyst portal (served by Nginx)
├── models/releases/            # Sealed model bundles & SHA-256 manifests
│   └── candidate_fusion_v30/   # Active production: URL + Vision + Fusion heads
├── scripts/                    # Training, benchmarking, and verification scripts
│   ├── tests/                  # 143 deployment & security-tool regressions
│   ├── e2e_v30_workflow_verify.py
│   ├── test_5k_actual_urls.py
│   ├── email_workflow_smoke.py
│   ├── frontend_workflow_smoke.py
│   └── security_scan.py
├── research/                   # Research notebooks and model governance tests
├── docs/                       # Architecture specs and benchmark reports
├── docker-compose.yml          # 13-container production deployment
└── README.md
```

---

## License

Licensed under the [Apache License 2.0](LICENSE).
