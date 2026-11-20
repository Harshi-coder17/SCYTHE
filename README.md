<div align="center">

<img src="chrome-extension/icons/red_logo_128.png" alt="SCYTHE Logo" width="96"/>

# SCYTHE

**Threat Shield · URL & Email Phishing Detection Platform**

[![CI](https://github.com/armaan-1207/SCYTHE/actions/workflows/verify.yml/badge.svg)](https://github.com/armaan-1207/SCYTHE/actions/workflows/verify.yml)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white)
![LightGBM](https://img.shields.io/badge/LightGBM-v31-brightgreen)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![Tests](https://img.shields.io/badge/tests-491%2B%20passing-success)
![License](https://img.shields.io/badge/license-MIT-blue)

*A production-grade, multi-layer phishing detection system with a Chrome extension, sandboxed URL detonation, email analysis, and a LightGBM fusion model trained on 428 K+ URLs.*

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [Project Structure](#-project-structure) · [Tech Stack](#-tech-stack) · [API Reference](#-api-reference) · [Chrome Extension](#-chrome-extension) · [CI / Security](#-ci--security)

</div>

---

## ✨ Features

| Category | Capability |
|---|---|
| 🔗 **URL Intelligence** | 28-feature extraction in ~107 µs · LightGBM inference in ~2.7 µs · end-to-end ~9.4 ms (P95 10.5 ms) |
| 📧 **Email Analysis** | Full MIME parsing, header forensics, embedded-URL extraction, IMAP polling, attachment scanning |
| 🖥️ **Sandbox Detonation** | Playwright-driven isolated browser execution · HAR capture · screenshot + DOM extraction |
| 👁️ **Visual AI** | MobileCLIP S0 screenshot embeddings · Neural MLP visual classifier (ROC-AUC 0.9585) |
| 🤖 **Fusion Model** | `candidate_fusion_v31` · 28 features · 600 trees · ROC-AUC **0.9824** on 21 997-URL holdout |
| 🧠 **Consistency Engine** | Cross-checks visual brand, OCR text, DOM structure, and URL for mismatch signals |
| 🛡️ **ClamAV Scanning** | Attachment malware scanning via ClamAV daemon with real-time signature updates |
| 🔒 **Auth & Rate-limiting** | JWT + Argon2 auth · HIBP breach check · account lockout · per-route rate limits |
| 🌐 **Chrome Extension** | Manifest V3 · real-time verdict badge · warning page · dark/light theme · auth bridge |
| 📡 **WebSocket Pushes** | Live scan progress and verdict streaming to the browser extension and dashboard |
| 🏗️ **13-container Stack** | Full Docker Compose deployment with healthchecks, hardened images, and resource limits |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  User / Browser                                                      │
│  ┌──────────────┐     HTTPS       ┌─────────────────────────────┐  │
│  │ Chrome Ext   │◄───────────────►│  scythe_nginx (TLS, :443)   │  │
│  │ (MV3)        │                 └────────────┬────────────────┘  │
│  └──────────────┘                              │                    │
└───────────────────────────────────────────────┼────────────────────┘
                                                 │ reverse proxy
                        ┌────────────────────────▼────────────────────┐
                        │  scythe_backend  (FastAPI / Uvicorn :8000)  │
                        │  ┌──────────┐ ┌──────────┐ ┌────────────┐  │
                        │  │ /scan/*  │ │ /email/* │ │  /auth/*   │  │
                        │  │ routes   │ │ routes   │ │  routes    │  │
                        │  └────┬─────┘ └────┬─────┘ └────────────┘  │
                        │       │   Celery tasks    │                  │
                        └───────┼───────────────────┼──────────────────┘
              ┌─────────────────┴──┐           ┌────┴──────────────────┐
              │  scythe_redis      │           │  scythe_postgres       │
              │  (broker + cache)  │           │  (users, scans, IOCs)  │
              └────────────────────┘           └───────────────────────┘
                        │
         ┌──────────────┴───────────────────────────────────┐
         │  Celery Workers                                   │
         │  ┌──────────────────┐  ┌───────────────────────┐ │
         │  │ celery_worker    │  │ celery_model_worker   │ │
         │  │ (OCR, vision,    │  │ (LightGBM v31 fusion) │ │
         │  │  consistency)    │  └───────────────────────┘ │
         │  └────────┬─────────┘                            │
         │           │ via docker_socket_proxy               │
         │  ┌────────▼──────────────┐  ┌─────────────────┐ │
         │  │ scythe_sandbox_runner │  │   scythe_clamav  │ │
         │  │ (Playwright, HAR)     │  │   (AV scanning)  │ │
         │  └────────┬──────────────┘  └─────────────────┘ │
         │           │ isolated network                      │
         │  ┌────────▼──────────────┐                       │
         │  │  sandbox container    │  (no route to core)   │
         │  └───────────────────────┘                       │
         └──────────────────────────────────────────────────┘
```

### Container Inventory

| # | Container | Role |
|---|---|---|
| 1 | `scythe_nginx` | TLS termination, reverse proxy, static dashboard |
| 2 | `scythe_backend` | FastAPI / Uvicorn API server (2 workers) |
| 3 | `scythe_postgres` | Primary datastore — users, scans, incidents, IOCs |
| 4 | `scythe_redis` | Celery broker + result backend + verdict cache |
| 5 | `scythe_redis_security` | Dedicated rate-limit & lockout store |
| 6 | `scythe_clamav` | ClamAV daemon for attachment AV |
| 7 | `scythe_celery_worker` | OCR, vision, sandbox dispatch, consistency engine |
| 8 | `scythe_celery_beat` | Periodic scheduler (cleanup, health sweeps) |
| 9 | `scythe_celery_model_worker` | LightGBM v31 inference worker |
| 10 | `scythe_celery_shadow_worker` | Shadow-scoring worker for A/B model validation |
| 11 | `scythe_socket_proxy` | Scoped Docker API proxy (sandbox isolation) |
| 12 | `scythe_sandbox_runner` | Playwright detonation orchestrator |
| 13 | `sandbox` | Fully isolated Playwright browser container |

---

## ⚡ Quick Start

### Prerequisites

| Tool | Minimum Version | Download |
|---|---|---|
| Docker Desktop | 24+ (with Compose v2) | [docker.com/get-started](https://www.docker.com/get-started/) |
| Git | 2.x | [git-scm.com](https://git-scm.com) |
| Node.js *(extension only)* | 20+ | [nodejs.org](https://nodejs.org) |

---

### 🐧 Linux / 🍎 macOS

```bash
# 1. Clone
git clone https://github.com/armaan-1207/SCYTHE.git
cd SCYTHE

# 2. Create secrets file (never commit this)
cp .env.production.example .env
#    Open .env and fill in every *_PASSWORD and SECRET_KEY field

# 3. Build and start the full stack
docker compose up -d --build --wait

# 4. Verify all 13 containers are healthy
docker compose ps

# 5. Open the dashboard
open https://localhost   # macOS
xdg-open https://localhost   # Linux
```

> [!NOTE]
> On first run, ClamAV downloads its virus definitions (~300 MB). The `clamav` service takes ~2–3 minutes to become healthy. All other services wait for it automatically.

---

### 🪟 Windows (PowerShell)

```powershell
# 1. Clone
git clone https://github.com/armaan-1207/SCYTHE.git
cd SCYTHE

# 2. Create secrets file
Copy-Item .env.production.example .env
# Edit .env — fill in every *_PASSWORD and SECRET_KEY field

# 3. Build and start
docker compose up -d --build --wait

# 4. Verify
docker compose ps

# 5. Open dashboard
Start-Process "https://localhost"
```

> [!TIP]
> On Windows, use **Docker Desktop with WSL 2 backend** for best performance. Make sure WSL 2 integration is enabled for your distro in Docker Desktop Settings.

---

### 🔑 Required `.env` Keys

```env
SECRET_KEY=<64-char hex>              # JWT signing key
SCYTHE_DB_PASSWORD=<strong-password>
POSTGRES_ROOT_PASSWORD=<strong-password>
REDIS_PASSWORD=<strong-password>
REDIS_SECURITY_PASSWORD=<strong-password>
SANDBOX_RUNNER_SECRET=<strong-password>
BACKUP_ENCRYPTION_KEY=<strong-password>

ENVIRONMENT=development               # or: production
CORS_ALLOWED_ORIGINS=https://localhost
ALLOWED_HOSTS=localhost,127.0.0.1
```

Generate strong secrets with:
```bash
# Linux / macOS
python3 -c "import secrets; print(secrets.token_hex(32))"

# Windows PowerShell
python -c "import secrets; print(secrets.token_hex(32))"
```

---

### Loading the Chrome Extension

1. Open **Chrome** → `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** → select the `chrome-extension/` folder
4. Click the SCYTHE shield icon → **Sign In** to your local instance

---

### Useful Commands

```bash
# View live logs
docker compose logs -f backend

# Run all backend tests
docker compose exec backend python -m pytest tests services/email/tests -q

# Run script/tooling tests
python -m pytest scripts/tests -q

# Stop the stack
docker compose down

# Full teardown (removes volumes)
docker compose down -v
```

---

## 📁 Project Structure

```
SCYTHE/
├── .github/
│   └── workflows/
│       └── verify.yml              # CI: backend, sandbox, quality, source-security
│
├── chrome-extension/               # Manifest V3 browser extension
│   ├── manifest.json
│   ├── background.js               # Service worker — scan triggers & WebSocket
│   ├── popup.js / popup.html       # Verdict UI with risk badge & detail panel
│   ├── auth-bridge.js              # JWT auth bridge (content script)
│   ├── content.js / bdr.js         # Page analysis content scripts
│   ├── warning.html / warning.js   # Full-page phishing warning
│   └── icons/                      # Green / orange / red verdict icons
│
├── containers/
│   ├── backend/                    # FastAPI application
│   │   ├── main.py                 # App entry point, middleware, WebSocket
│   │   ├── config.py               # Settings (Pydantic BaseSettings)
│   │   ├── risk_fusion.py          # Feature vector construction & model dispatch
│   │   ├── api/
│   │   │   ├── routes.py           # URL scan endpoints
│   │   │   └── email_routes.py     # Email scan endpoints
│   │   ├── auth/                   # JWT, Argon2, HIBP, lockout
│   │   ├── ai_engine/              # OCR, vision (MobileCLIP), DOM extractor, NLP
│   │   ├── consistency_engine/     # Brand/visual/OCR mismatch detection
│   │   ├── cyberintel/             # Threat-feed lookups
│   │   ├── email_engine/           # MIME parser, IMAP poller, URL extraction
│   │   ├── services/
│   │   │   ├── model_features/
│   │   │   │   └── url_features.py # 28-feature URL extractor (V3 contract)
│   │   │   ├── model_release.py    # Checksum-verified model bundle loader
│   │   │   └── sandbox_runner_svc.py
│   │   ├── tasks/                  # Celery task definitions
│   │   ├── models/                 # LightGBM .txt + metrics.json + calibration
│   │   ├── schemas/                # Pydantic request/response schemas
│   │   ├── database/               # SQLAlchemy models + Alembic migrations
│   │   ├── tests/                  # 309 backend tests
│   │   ├── requirements.txt        # Pinned + hashed production deps
│   │   └── Dockerfile / Dockerfile.worker / Dockerfile.shadow
│   │
│   ├── sandbox/                    # Playwright detonation container
│   │   ├── backend/                # Sandbox API
│   │   └── tests/                  # 13 SSRF / egress / HAR tests
│   │
│   ├── nginx/                      # Hardened Nginx + TLS config
│   ├── postgres/                   # DB init scripts
│   └── vendor/                     # Hardened Redis image
│
├── scripts/                        # Tooling, training & research scripts
│   ├── security_scan.py            # Gitleaks + Bandit + pip-audit gate
│   ├── lint_changed.py             # Ruff gate on changed files only
│   ├── test_extension_auth.cjs     # Node.js extension regression tests
│   ├── train_v31_28feature_booster.py
│   ├── train_expanded_visual_head_v31.py
│   └── tests/                      # 143+ script-level tests
│
├── docker-compose.yml              # 13-container development stack
├── docker-compose.prod.yml         # Production overrides
├── Makefile                        # Common dev shortcuts
└── DEPLOYMENT_CHECKLIST.md        # Production go-live checklist
```

---

## 🔬 ML Model — `candidate_fusion_v31`

### URL Feature Contract V3 (28 features)

| # | Feature | Description |
|---|---|---|
| 1 | `url_length` | Total URL character count |
| 2 | `host_length` | Hostname character count |
| 3 | `is_https` | HTTPS scheme flag |
| 4 | `is_ip_host` | IP address instead of domain |
| 5 | `subdomain_count` | Number of subdomain labels |
| 6 | `hyphen_count` | Hyphens in hostname |
| 7 | `digit_count` | Digits in full URL |
| 8 | `special_count` | Special characters in URL |
| 9 | `at_symbol` | `@` present in URL |
| 10 | `question_mark_count` | Query string count |
| 11 | `path_length` | URL path length |
| 12 | `query_length` | Query string length |
| 13 | `has_punycode` | Punycode / IDN encoding |
| 14 | `url_shortener_used` | Known shortener domain |
| 15 | `is_bogon_space` | RFC-1918 / bogon IP host |
| 16 | `is_paas_subdomain` | PaaS platform (Vercel, Netlify…) |
| 17 | `subdomain_entropy` | Shannon entropy of subdomain |
| 18 | `brand_in_subdomain_mismatch` | Protected brand in subdomain ≠ registrable domain |
| 19 | `tld_abuse_risk` | High-abuse TLD score |
| 20 | `digit_ratio_host` | Digit density in hostname |
| 21 | `digit_ratio_url` | Digit density in full URL |
| 22 | `vowel_ratio_domain` | Vowel ratio (DGA signal) |
| 23 | `directory_depth` | Path segment depth |
| 24 | `path_longest_token_length` | Longest token in path |
| 25 | `has_credential_keyword` | Sensitive keyword (`login`, `verify`…) |
| 26 | `consecutive_special_chars` | Runs of consecutive special chars |
| 27 | `non_standard_port` | Non-80/443 port in URL |
| 28 | `tld_in_subdomain` | TLD string appearing inside subdomain |

### Model Performance

| Metric | Validation | Holdout (21 997 URLs) |
|---|---|---|
| ROC-AUC | 0.9906 | **0.9824** |
| PR-AUC | — | 0.9891 |
| Precision | 99.6% | 99.6% |
| Recall | 96.4% | 94.2% |
| F1 | 98.0% | 96.8% |
| FP per 10 000 benign | 25 | 25 |

**Training corpus**: 428 222 URLs · **Trees**: 600 · **Feature extraction**: ~107 µs/URL · **Inference**: ~2.71 µs/URL

---

## 🧰 Tech Stack

### Backend
| Component | Technology |
|---|---|
| API Framework | **FastAPI** + Uvicorn (async, ASGI) |
| Task Queue | **Celery** 5.4 with Redis broker |
| Database | **PostgreSQL** 16 (SQLAlchemy + Alembic migrations) |
| Cache / Broker | **Redis** 7.2 (hardened Alpine image) |
| ML Inference | **LightGBM** (gradient-boosted trees, 28 features) |
| Visual AI | **MobileCLIP S0** (Apple) + PyTorch Neural MLP |
| OCR | **Tesseract** via pytesseract |
| Email Parsing | **mail-parser** + custom IMAP poller |
| AV Scanning | **ClamAV** daemon |
| Browser Automation | **Playwright** (Chromium, isolated sandbox) |
| Auth | **JWT** (HS256) + **Argon2** password hashing |
| Logging | **structlog** (JSON in production) |

### Infrastructure
| Component | Technology |
|---|---|
| Containerisation | **Docker Compose** v2 (13 services) |
| Reverse Proxy | **Nginx** (TLS 1.3, HSTS, hardened) |
| Container Security | `cap_drop: ALL`, UID 10001, `no-new-privileges`, read-only rootfs |
| Secret Management | Environment variables via `.env` (never committed) |

### Chrome Extension
| Component | Technology |
|---|---|
| Manifest | **MV3** (service worker background) |
| Auth | JWT bridge via `auth-bridge.js` content script |
| Comms | WebSocket + REST to SCYTHE backend |
| UI | Vanilla JS / CSS, light + dark themes |

### CI / Quality
| Component | Technology |
|---|---|
| Lint | **Ruff** 0.15 (changed-files gate) |
| Workflow lint | **actionlint** 1.7.12 |
| Secret scanning | **Gitleaks** 8.30 |
| SAST | **Bandit** 1.9 |
| Dependency audit | **pip-audit** 2.10 |
| Tests | **pytest** (491+ total: 309 backend + 143 scripts + 13 sandbox + 1 lint) |

---

## 📡 API Reference

All endpoints require `Authorization: Bearer <jwt>` except `/auth/*` and `/`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Health check |
| `POST` | `/auth/register` | Register a new user |
| `POST` | `/auth/login` | Obtain JWT token |
| `POST` | `/auth/refresh` | Refresh JWT token |
| `POST` | `/scan/quick` | URL-only phishing score (sub-10 ms) |
| `POST` | `/scan/full` | Full pipeline: sandbox + vision + consistency + fusion |
| `GET` | `/scan/{id}` | Retrieve scan result by ID |
| `GET` | `/scan/history` | Paginated scan history |
| `POST` | `/email/analyze` | Analyze raw `.eml` / MIME email |
| `GET` | `/email/history` | Email analysis history |
| `WS` | `/ws/scan/{id}` | Live scan progress WebSocket stream |

---

## 🌐 Chrome Extension

The **SCYTHE Threat Shield** extension (Manifest V3) provides real-time phishing protection directly in the browser.

```
chrome-extension/
├── background.js     # Service worker: intercepts navigation, dispatches scans
├── popup.js          # Verdict badge (green/orange/red) + detail panel
├── auth-bridge.js    # Content script: injects JWT auth headers
├── content.js        # Page DOM analysis
├── bdr.js            # Brand detection & risk signalling
├── warning.html      # Full-page block screen for high-risk URLs
└── config.js         # Backend endpoint configuration
```

**How it works:**
1. `background.js` intercepts `webNavigation.onCompleted` and fires a quick scan
2. The popup shows the live verdict badge with score and confidence
3. For high-risk verdicts, `warning.html` replaces the page
4. Auth state is managed via the JWT bridge — no credentials touch the DOM

---

## 🔐 CI / Security

### GitHub Actions (`verify.yml`)

| Job | What it checks |
|---|---|
| `backend` | 309 backend + email regression tests (pytest) |
| `sandbox` | 13 SSRF / egress / HAR isolation tests |
| `quality` | Actionlint, Ruff lint (changed files), JS syntax + extension auth regression |
| `source-security` | Gitleaks secret scan, Bandit SAST, pip-audit dependency CVE gate |
| `compose-browser-workflow` | Manual — full Playwright E2E + Trivy image scan |

### Security Posture

- ✅ **0** Bandit HIGH/MEDIUM findings
- ✅ **0** Gitleaks credential leaks
- ✅ **0** unmitigated CVEs (documented rationale for all ignored advisories)
- ✅ All containers: `cap_drop: ALL`, UID 10001, `no-new-privileges: true`
- ✅ Sandbox isolated on `sandbox_net` with **no route** to `scythe_net`
- ✅ Docker socket access via scoped proxy (`CONTAINERS=1`, `IMAGES=1` only)
- ✅ TLS 1.3 only, HSTS, `X-Frame-Options`, `Referrer-Policy` enforced
- ✅ Rate-limiting, account lockout, HIBP breach detection on auth endpoints

---

## 📊 Test Coverage

```
Backend tests      309   (API, auth, model, email, rate-limit, lockout, backup)
Sandbox tests       13   (SSRF, egress-proxy, HAR redaction)
Script tests       143   (security scan, lint gate, model release, qualification)
Lint test            1   (changed-file lint gate regression)
─────────────────────
Total             491+
```

---

## 🤝 Contributing

1. Fork the repo and create a feature branch
2. Run the full test suite: `python -m pytest scripts/tests containers/backend/tests -q`
3. Ensure lint passes: `python scripts/lint_changed.py`
4. Ensure security passes: `python scripts/security_scan.py --checks secrets sast deps`
5. Open a pull request — CI runs all gates automatically

---

## 👥 Authors

| Contributor | Role |
|---|---|
| **armaan-1207** | Core architecture, ML pipeline, backend, Chrome extension |
| **Harshi-coder17** | Test infrastructure, lint gate, CI improvements |

---

<div align="center">

Made with ☕ and far too many CVE advisories.

**SCYTHE** · MIT License

</div>
