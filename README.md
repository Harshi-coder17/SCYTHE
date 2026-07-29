# SCYTHE
### Secure Cyber & Threat Heuristics Engine

> A production-grade, containerized phishing detection and threat intelligence platform.
> SCYTHE intercepts, sandboxes, and dissects malicious URLs — exposing cloaked phishing pages before they can claim victims.

---

## What It Does

SCYTHE is a multi-stage automated pipeline that takes a suspicious URL and tears it apart:

1. **Browser Capture** — Headless browser visits the URL, captures a full screenshot and raw DOM.
2. **Sandbox Execution** — An isolated container re-visits the URL from a clean environment, detecting cloaking and evasion.
3. **Consistency Engine** — Compares browser vs. sandbox views to detect if the site serves different content to different visitors (cloaking).
4. **Threat Intelligence** — Concurrently queries VirusTotal, OTX, Shodan, and IPInfo for known indicators of compromise.
5. **Risk Fusion** — Aggregates all signals into a unified risk score and verdict.

---

## Architecture

```
SCYTHE/
├── chrome-extension/     # Browser extension — submits URLs for scanning
├── containers/           # All Docker services
│   ├── backend/          # FastAPI core — auth, scanning, task queue
│   ├── celery_worker/    # Async task processor
│   ├── celery_beat/      # Scheduled task scheduler
│   ├── sandbox/          # Isolated URL execution environment
│   ├── redis/            # Task broker & result cache
│   ├── nginx/            # Reverse proxy
│   └── docker_proxy/     # Secure Docker socket proxy
├── dashboard/            # React frontend — scan results & analytics
├── docs/                 # Architecture docs & API reference
├── scripts/              # Dev utilities & deployment helpers
└── shared/               # Bind-mounted host volume for scan artifacts
    ├── scans/            # Per-scan output directories
    ├── emails/           # Email artifact storage
    └── files/            # File upload analysis storage
```

---

## Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI (Python) |
| Task Queue | Celery + Redis |
| Containerization | Docker + Docker Compose |
| Browser Automation | Playwright (headless Chromium) |
| Threat Intelligence | VirusTotal, OTX, Shodan, IPInfo |
| Frontend | React |
| Browser Extension | Chrome Extension (Manifest V3) |
| Reverse Proxy | Nginx |

---

## Quick Start

```bash
# Clone the repo
git clone <your-repo-url>
cd SCYTHE

# Configure environment
cp .env.example .env
# Fill in your API keys in .env

# Start all services
docker compose up --build -d

# Run a scan
python run_scan.py --url "https://suspicious-site.example.com"
```

Scan artifacts are written to `./shared/scans/<scan_id>/` on your local machine.

---

## Environment Variables

| Variable | Description |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `OTX_API_KEY` | AlienVault OTX API key |
| `SHODAN_API_KEY` | Shodan API key |
| `IPINFO_TOKEN` | IPInfo access token |
| `SECRET_KEY` | JWT signing secret |
| `POSTGRES_*` | Database connection settings |

---

## Scan Output

Each scan produces a structured output directory:

```
shared/scans/<scan_id>/
├── browser.png               # Headless browser screenshot
├── browser.html              # Captured DOM
├── sandbox.png               # Sandbox screenshot
├── sandbox_metadata.json     # Sandbox execution metadata + DOM content
├── consistency_report.json   # Cloaking detection result
├── threat_intel.json         # VirusTotal / OTX / Shodan findings
└── final_report.json         # Unified risk score & verdict
```

---

## Project Structure Details

| Directory | README |
|---|---|
| `chrome-extension/` | [Chrome Extension](./chrome-extension/Readme.md) |
| `containers/` | [Backend Services](./containers/Readme.md) |
| `dashboard/` | [Dashboard UI](./dashboard/Readme.md) |
| `docs/` | [Documentation](./docs/Readme.md) |
| `scripts/` | [Scripts & Utilities](./scripts/Readme.md) |
| `shared/` | [Shared Volumes](./shared/Readme.md) |

---

*SCYTHE — Because phishing pages don't get to hide.*
