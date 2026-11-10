# SCYTHE — Security Pending Human Actions

**Document ID:** `SCYTHE-SEC-PENDING-20261025`  
**Date:** October 25, 2026  
**Prepared By:** Antigravity Autonomous Security Subagent (Track C)  
**Authorized By:** User (explicit authorization: "do both in parallel and check and fix these too if applicable")

---

## Overview

This document enumerates the security and compliance tasks that **require direct human operator action** and cannot be automated by the agent. Each item below is a hard gate or irreversible action that must be performed by a qualified person with the appropriate credentials, institutional authority, or physical access.

---

## Action 1: Docker Image Rebuild with Updated brotli/filelock Pins

**Priority:** MEDIUM-HIGH  
**Category:** Container Security  
**Blocking:** Production image security posture for brotli/filelock CVEs

### Background

Two Python sub-dependency security pins were added to `containers/backend/requirements.in`:

```
brotli>=1.2.1      # GHSA-9v8h-qqgm-4m35
filelock>=4.2.1    # CVE-2026-112940
```

`requirements.txt` is a compiled, hash-pinned lock file and **cannot be regenerated inside containers** (pip is removed from the runtime image by design). The pins in `requirements.in` have no effect on currently running containers until the image is rebuilt.

### Steps Required

1. **Run pip-compile** on a trusted developer workstation with pip-tools installed:
   ```bash
   cd containers/backend
   pip-compile --generate-hashes requirements.in -o requirements.txt
   ```
   Verify the output `requirements.txt` contains `brotli>=1.2.1` and `filelock>=4.2.1` hashes.

2. **Rebuild the Docker image:**
   ```bash
   docker build -t scythe-backend:latest containers/backend/
   docker build -t scythe-celery_model_worker:latest containers/backend/
   # (and any other derived worker images sharing the base)
   ```

3. **Push to registry:**
   ```bash
   docker push <registry>/scythe-backend:latest
   docker push <registry>/scythe-celery_model_worker:latest
   ```

4. **Perform a controlled rolling restart** of the affected containers via `docker compose up -d --no-deps <service>` or your production orchestration tooling.

5. **Verify** the newly running images carry `brotli>=1.2.1` and `filelock>=4.2.1` in `pip show`:
   ```bash
   docker exec scythe_backend pip show brotli filelock
   ```
   *(Note: `pip` will not be present in the runtime image after rebuild — verify via `python -c "import brotli; print(brotli.__version__)"` instead.)*

> **⚠️ DO NOT restart containers on the live system without a maintenance window or rolling-deploy strategy.** The 13-container platform is currently healthy and serving traffic.

---

## Action 2: PhiShark 2026 DUA Institutional Signature

**Priority:** HIGH  
**Category:** Legal / Compliance  
**Blocking:** Use of PhiShark 2026 dataset in training/evaluation

### Background

The PhiShark 2026 dataset is governed by a Data Use Agreement (DUA) that requires a qualified institutional signatory (typically a department head, PI, or legal representative).

### Steps Required

1. Obtain the current DUA document from the PhiShark 2026 data access portal.
2. Route to the appropriate institutional authority for review and wet/digital signature.
3. Submit the signed DUA to the data provider.
4. Receive and archive the executed agreement.
5. Store the signed document in `docs/legal/phishark2026_dua_signed.pdf` and update `docs/DATA_GOVERNANCE.md`.

> **This must be completed before PhiShark 2026 data is used in any holdout evaluation or production model training.**

---

## Action 3: CISA .gov Playwright Domain Capture Execution (≥ 5,000 Domains)

**Priority:** HIGH  
**Category:** Training Data / Dataset Construction  
**Blocking:** Legitimate-domain dataset completeness for holdout evaluation

### Background

A Playwright-based web capture pipeline exists to harvest browser features, screenshots, and DOM snapshots from `.gov` domains listed in CISA's dotgov dataset. A minimum of **5,000 unique domains** must be captured to meet the statistical power requirements for the holdout evaluation.

### Steps Required

1. Ensure the CISA `.gov` domain list is current (download from `https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv`).
2. Launch the Playwright capture job on a machine with:
   - Sufficient outbound internet access (`.gov` domains)
   - A non-rate-limited IP range or proxy rotation
   - At least 50 GB free disk space for artifacts
3. Run the capture with the appropriate concurrency setting:
   ```bash
   python scripts/capture_domains.py \
       --input data/cisa_dotgov_current.csv \
       --output data/captures/gov/ \
       --min-domains 5000 \
       --concurrency 8
   ```
4. Verify capture completion: `≥ 5,000` domains with valid `browser.png`, `dom.html`, and `features.json` artifacts.
5. Update `docs/DATASET_STATUS.md` with capture run metadata (date, count, SHA-256 manifest).

> **This capture must be run in a controlled environment. Do not run on the production SCYTHE server — it will generate high outbound traffic that may interfere with normal platform operations.**

---

## Action 4: Production MODEL_RELEASE_ENABLED=true Toggle

**Priority:** CRITICAL — IRREVERSIBLE PRODUCTION CHANGE  
**Category:** Model Release Gate  
**Blocking:** v22 candidate bundle activation in production

### Background

The SCYTHE platform currently operates in fail-closed mode with `MODEL_RELEASE_ENABLED=false` enforced across all 5 model-serving containers. Activating the v22 candidate bundle requires toggling this flag to `true` — a one-way gate that enables live neural network inference in production.

### Prerequisites — ALL MUST BE MET BEFORE TOGGLING

- [ ] **Holdout evaluation passed:** The v22 bundle (`candidate_fusion_v22_trained/`) must pass a qualified holdout evaluation with the required precision/recall thresholds.
- [ ] **PhiShark 2026 DUA signed** (Action 2 above).
- [ ] **CISA .gov capture complete** (Action 3 above, ≥ 5,000 domains).
- [ ] **Docker image rebuild complete** with brotli/filelock pins (Action 1 above).
- [ ] **Trust anchor confirmed:** SHA-256 trust anchor `4a8369295729392cffff28e76a3670b28127361802d83ba122a9f4ddfac040ec` must match the `checksums.sha256` file inside the v22 bundle directory.
- [ ] **Confmat validation passed:** `validate_qualification_summary()` must return `True` for the v22 bundle.
- [ ] **Peer sign-off:** At least one additional qualified engineer must review and approve the activation.

### Steps Required (After All Prerequisites Met)

1. Update `docker-compose.yml` (or environment override): set `MODEL_RELEASE_ENABLED=true` for all 5 model-serving services.
2. Set `MODEL_RELEASE_BUNDLE_DIR` to point to the mounted v22 bundle path.
3. Set `MODEL_RELEASE_CHECKSUMS_SHA256` to the trust anchor hash.
4. Perform a rolling container restart.
5. Monitor for 15+ minutes: check inference logs, scan outputs, and incident pipeline for anomalies.
6. Confirm first post-activation scan returns `is_placeholder: false` with a valid `risk_score`.
7. Update `docs/SECURITY_OPERATIONS_FINAL_REPORT_20261025.md` with activation timestamp and signing engineer names.

> **⚠️ CAUTION: DO NOT toggle MODEL_RELEASE_ENABLED=true until every prerequisite above is checked. Premature activation with an unvalidated model will produce unreliable risk scores in production and cannot be easily rolled back without a container restart.**

---

## Summary Table

| # | Action | Priority | Estimated Effort | Blocking |
|---|--------|----------|-----------------|---------|
| 1 | Docker rebuild with brotli/filelock pins | MEDIUM-HIGH | 1–2 hours | brotli/filelock CVE closure |
| 2 | PhiShark 2026 DUA institutional signature | HIGH | Days–weeks (legal routing) | Holdout evaluation |
| 3 | CISA .gov Playwright capture (≥5,000 domains) | HIGH | 4–12 hours compute | Holdout evaluation |
| 4 | `MODEL_RELEASE_ENABLED=true` toggle | CRITICAL | 30 min (+ all prerequisites) | v22 production deployment |

---

*Document prepared as part of Track C (Item 5) of the SCYTHE production release process. All automated checks (C1–C6) completed and signed off. Human actions above are the remaining gates before v22 can be considered for production activation.*
