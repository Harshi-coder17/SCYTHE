# Security & Vulnerability Advisory Assessment

## 1. Executive Summary

### Current update — 21 October 2026

The fresh audit found advisories affecting Pillow 12.3.0 and certifi
2026.7.22. Active application locks now use Pillow 13.0.0 and certifi
2026.10.19. Patched local API, worker, beat, inference, research and sandbox
images were built from verified offline wheels. Existing frozen experiment
locks remain historical; they were not rewritten to claim patched training.

The subsequent SAST and all four Python dependency audits passed. Fresh Trivy
scans still fail: backend has 44 High findings, inference 49 High, and browser
sandbox 63 High plus one Critical. None lists a fixed package version in these
reports. These remain open release findings; non-root users, restricted egress,
separate queues and bounded execution mitigate exposure but do not clear them.

Evidence: `../../audit-output/security_patched_20261021_v1/summary.json`,
`../../audit-output/security_images_patched_20261021_v1/concise_findings.json`,
and `../../audit-output/security_runtime_patch_20261021_v1/deployment.json`.
Earlier dated scans below describe their own frozen images, not current
vulnerability counts or the complete current dependency coverage.

This document records the current security posture of the SCYTHE platform across source code, application dependencies, secrets scanning, and container base images as evaluated by `scripts/security_scan.py`.

The repository is **not** described as fully security-cleared due to open upstream OS package advisories in base Docker container images. Application-level source code and locked Python dependencies pass all scans cleanly.

---

## 2. Scan Results by Domain

### A. Static Application Security Testing (SAST) — PASS
- **Tool**: Bandit v1.9.4
- **Targets**: `containers/backend/`, `containers/sandbox/backend/`
- **Result**: **0 High, 0 Medium** actionable vulnerabilities found.
- **Coverage**: Recursive Bandit scan of Python files under the two listed directories. Bandit reports 0 high/medium severity findings in this run; low-severity findings remain in its JSON output. This is static analysis, not a manual review or proof that the code is vulnerability-free.

### B. Python Dependency Vulnerability Audits — PASS
- **Tool**: `pip-audit` v2.10.1
- **Targets**:
  - `containers/backend/requirements.txt`: **No known vulnerabilities found (PASS)**
  - `containers/backend/requirements.runner.txt`: **No known vulnerabilities found (PASS)**
  - `containers/sandbox/docker/requirements.txt`: **No known vulnerabilities found (PASS)**

### C. Secret Leak Scanning — PASS
- **Tool**: Gitleaks
- **Configuration**: `.gitleaks.toml`
- **Result**: The repository security helper scanned a temporary snapshot of Git-tracked plus untracked, non-ignored repository files; the snapshot scan passed with no findings. It does **not** scan Git history. Ignored local `.env` and `.venv` files are intentionally excluded. A separate raw whole-directory run produced generic-key matches in those ignored paths and a vendored Python library; those were outside the repository snapshot result and their values are redacted. Do not describe the helper result as a Git-history audit.

### D. Base Container Image Vulnerabilities — OPEN UPSTREAM ADVISORIES
- **Tool**: Trivy (`--scanners vuln --severity HIGH,CRITICAL`)
- **Images Analyzed**: The 2026-10-17 local image scan covered backend, Celery worker, Celery beat, shadow worker, sandbox runner, Nginx, browser sandbox, Redis, socket proxy, ClamAV, PostgreSQL, and the Alpine network helper.
- **Findings**: The pinned scan passed Nginx, Redis, socket proxy, ClamAV, and the Alpine helper. It still reports 44 high findings for backend and sandbox runner; 75 high plus 1 critical each for worker and beat; 54 high for shadow worker; 67 high plus 1 critical for browser sandbox; and 24 high plus 1 critical for PostgreSQL. See `../../audit-output/image-security-after-rebuild-20261017/summary.json` and its per-image reports. These are package-level scanner findings; some have no scanner-reported fixed version. The report does not claim all findings are exploitable or resolved.
- **Mitigation & Posture**:
  1. The backend and sandbox-runner application processes use UID/GID 10001; supporting images retain their image-specific runtime users. Verify each service configuration rather than assuming one account is used by every container.
  2. The browser sandbox uses Docker seccomp profiles, a read-only root filesystem, and controlled egress through the configured proxy. These controls reduce exposure; they do not clear image CVEs.
  3. Keep the image gate open until each finding is fixed or assessed with evidence, then rebuild and rescan pinned images.

## 2026-10-19 renderer and OS follow-up

The browser image now refreshes OS upgrades in the multilingual-font layer. This
installs `libexpat1` version `2.9.0-1~deb13u1`, clearing the five scanner-reported
high findings affecting the previously installed version. Source pinning and
the runner were updated only at an idle capture boundary; the trained model
was not activated. The installed Noto Core, CJK, and emoji fonts pass an offline
Chinese, Japanese, Korean, Thai, Hindi, Arabic, and emoji coverage/render test.
A public IANA `example.org` passive capture also passed with the normal isolated
container shape and egress guard. These checks do not establish model quality.

The critical `libxml2` finding remains open, with no stable Trixie package fix
reported by Debian. Debian classifies CVE-2026-6653 as a minor issue with no DSA;
the tracker describes an XML entity-parser use-after-free causing denial of
service. This vendor assessment does not mean the scanner finding is fixed or
that all application paths are proven unreachable. The upstream fix changes
entity accounting and public structures across several files, so it was not
applied as an untested local ABI-changing patch. See the
[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-6653) and
[upstream change](https://github.com/GNOME/libxml2/commit/463bbeeca1805b5c4828f50d0fefc4eebaf620df).

An isolated image experiment removed unused GTK dependencies while preserving
Chromium's direct libraries. Offline browser, OpenCV, and QR-library checks
passed, but the XML library remains required through Mesa/LLVM and the image
scan still fails. That experiment was not promoted. It does not justify a
global vulnerability exception or a claim of a clean image.

Evidence is retained under `../../audit-output/sandbox-security-patch-20261019/`,
`../../audit-output/capture-fonts-global-20261019/`,
`../../audit-output/image-security-patched-20261019/`, and
`../../audit-output/image-security-global-font-patched-20261019/`. The earlier
Trixie and Bookworm reports remain historical evidence. Python SAST and all
three locked Python dependency audits passed in the host scanner environment;
an initial run in the project virtual environment recorded missing scanner
tools and is not presented as a clean scan.

## Model-worker audit coverage correction (2026-10-19)

The dependency gate now includes `containers/backend/requirements.shadow.txt`,
which was absent from the earlier three-file audit. A zero scanner exit is no
longer accepted when its JSON reports skipped dependencies or missing coverage.
The CPU-local versions `torch==2.8.0+cpu` and `torchvision==0.23.0+cpu` were skipped
by pip-audit because those distributions are not found on PyPI. This is an
unresolved audit-coverage gap, not evidence of a vulnerability or a clean result.
No automatic version normalization or global exception was used to hide it.

The corrected four-file run is recorded in
`../../audit-output/security-model-worker-coverage-20261019/summary.json` and
fails explicitly for the two unaudited wheels. The preceding diagnostic run
under `security-model-worker-20261019` is retained to show why process-exit-only
checking was insufficient. The three original requirement sets still pass.
The active sandbox image scan records 63 high and one critical package findings;
none has a scanner-reported fixed version in that saved report. This does not
constitute acceptance of the remaining findings.

Manual primary-source follow-up also found
[PyTorch GHSA-2rj9-7h5r-q4h8](https://github.com/pytorch/pytorch/security/advisories/GHSA-2rj9-7h5r-q4h8).
The upstream advisory lists versions through 2.8.0 as affected and 2.9.0 as
patched for the bundled tensorpipe/libuv hostname-resolution issue. The pinned
2.8.0 CPU runtime falls within that version range. The advisory rates it
moderate; direct exploitability through SCYTHE's image inference is not
established. A version range finding must not be described as a demonstrated
SCYTHE exploit or as fixed merely because distributed RPC is not intentionally
used. A patched CPU runtime requires a separate compatible build and renewed
encoder/prediction parity checks; frozen candidate manifests remain unchanged.

The subsequent exact-version OSV audit **does** support the CPU wheel versions.
It reports eight advisory records for `torch==2.8.0+cpu`, including the
weights-only unpickler issue CVE-2026-24747 (reported fixed in 2.10.0). Results
are saved without version rewriting in
`../../audit-output/security-model-worker-coverage-20261019/shadow-osv.json`.
The automated gate now selects OSV for the shadow requirements, retains the
chosen service in its summary, and still rejects missing/skipped coverage.
The original PyPI coverage failure remains historical evidence. A 2.9 upgrade
alone would not address all reported records. Scanner applicability ranges,
upstream fixes and actual inference paths require review; this is not proof
that all eight issues are remotely exploitable through SCYTHE.

## Patched model-runtime follow-up (2026-10-20 local)

The source inference pins now use the official CPU wheels
`torch==2.14.1+cpu` and `torchvision==0.29.1+cpu`. Import/dependency checks and
versioned compatibility verification against frozen v6 were performed separately
from its historical training environment. The original v6 model files and
2.8 training lock were preserved. The candidate compatibility report is under
`../../audit-output/local-release-runtime-20261020/worker_report_v6_torch2141.json`.

The corrected SAST plus four-requirement-set audit passed, including exact CPU
versions queried through OSV, with no known findings in that run. Evidence:
`../../audit-output/security-patched-model-worker-20261020/summary.json`.
The earlier eight-advisory result is retained as the remediation baseline.
This clears the reported Python advisory set for the updated source pins; it
does not certify container OS packages, unlisted transitive dependencies, model
quality, or production activation. Container-image findings remain separately
open. Image build/deployment identities and compatibility limitations are
recorded in the local-release operations report.

## Exact deployed-image refresh (20 October 2026, 07:12–07:19 UTC)

A fresh vulnerability database and checksum-pinned Trivy 0.76 scanned the actual patched shadow image `sha256:85ccaf181c8bc698adeccbe1765d9c6c863e586c32d1154f1aa84ff4fa1521c4` and the unchanged active sandbox digest `c10140e89411622b4c6331e440690d186f5b7c9f279cf1d88c589379763ac54c`. The image-security gate **fails**: shadow has 49 HIGH package findings across 10 unique CVEs; sandbox has 63 HIGH and one CRITICAL package findings across 22 unique CVEs. Multiple binary packages share source-package CVEs; these are not counts of independent exploits. Detected Python/Node metadata produced zero HIGH/CRITICAL findings in this scan, without implying complete dependency or OS clearance.

None of these current HIGH/CRITICAL records contains a scanner-reported fixed version. Disposable containers created from each exact image refreshed stable repository metadata and simulated upgrades: both reported zero upgrades and zero new installations. The sandbox's installed and stable-candidate libxml2 versions are both `2.12.7+dfsg+really2.9.14-2.1+deb13u3`. This establishes that there is **no supported stable package upgrade available in the observed repositories**, rather than just assuming a rebuild will fix the findings. Active containers, image layers, capture configuration, credentials and advisory exclusions were unchanged by these probes.

Primary vendor trackers corroborate representative dispositions: [libxml2 CVE-2026-6653](https://security-tracker.debian.org/tracker/CVE-2026-6653), [util-linux CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642), and [systemd CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) remain vulnerable in Trixie and are classified no-DSA/minor issues; [Perl CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) is postponed while upstream regressions are addressed. Listed fixes in unstable/testing are not compatible stable security updates automatically suitable for these images. Twenty-one of 24 requested Debian tracker pages were saved with hashes; three unavailable fetches remain explicit in the index and are not represented as independently corroborated.

The util-linux report concerns privileged mount hooks, the systemd report concerns homed-managed local users, and the Perl report concerns parsing malicious tar sizes. Those conditions differ from ordinary model inference. The shadow service runs non-root with all capabilities dropped and no-new-privileges; its model/shadow scoring flags remain false. The sandbox uses bounded isolated capture and egress controls. These are mitigations, not demonstrated universal unreachability or fixes. libxml2's XML-parser finding remains explicitly open.

The concrete next package-update action is to consume a supported vendor security update when published, rebuild at an idle collection boundary, rerun inference/capture compatibility tests, and rescan. No currently available compatible fixed-version update was identified. Reducing unused packages or changing the base is a separate compatibility experiment and cannot be substituted for a passing image gate. The checksummed reports, raw primary-source snapshots, simulated-upgrade outputs and per-image disposition are in `../../audit-output/image-security-shadow-deployed-20261020-v1/`. No global ignore or security waiver was added.
