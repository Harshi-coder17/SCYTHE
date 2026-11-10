# File and mailbox diagnostic workflows

The default upload endpoint now runs the v10 task topology instead of synchronous work in the API process:

`POST /api/scans/file` → durable owned Scan/payload → parallel SHA256, static, ClamAV tasks → bounded content inspection → consistency/report persistence.

Upload returns `scan_id`, `file_id`, `status=file_analysis_queued`, and `job_id`. A matching cache hit can return `file_scan_done` immediately. Poll `GET /api/scans/{scan_id}` and inspect `risk_report`; the existing ownership checks apply to metadata and report downloads. Files live under `SHARED_DIR/files/{scan_id}` and canonical reports under `SHARED_DIR/{scan_id}/risk_report.json`. Metadata records the user and scan association for retention. The synchronous Python helper remains for compatibility/tests; it also persists canonical reports.

AV errors and changed payload hashes produce `file_scan_unavailable`, null risk, `UNKNOWN`, and no reusable verdict cache. Task failures receive the same unavailable treatment. Broker failures return HTTP503 and mark `file_dispatch_failed`. Static extension-sensitive cache keys remain `filescan:v2:{sha256}:{extension}`. Every upload/cache hit receives a new owned identity. Cache/report delivery does not grant the caller access to earlier users' artifacts.

Files are never executed. Content inspection reads ZIP metadata with entry and expanded-size limits, detects an Office VBA project, and retains existing PDF active-content/static rules. This is bounded static evidence, not a malware detonation or semantic document model. File scores are explicitly `score_type=static_heuristic`, `heuristic_only=true`, `is_placeholder=true`, `automatic_decision=false`. The production model/incident gate remains unchanged.

## Mailbox authorization and operations

The optional Compose `mailbox` profile runs `email_poller`; the default stack never opens a mailbox. Provision all of the following locally before explicitly enabling it:

- `EMAIL_OWNER_USER_ID`: an existing active user's UUID, assigned by the operator.
- `EMAIL_ADDRESS`: the exact monitored mailbox assigned to that user.
- `EMAIL_POLLER_TOKEN`: a dedicated random token of at least32 characters, shared only by backend and collector.
- IMAP host and OAuth2/app-password credentials through the ignored local environment.

The collector receives only its mailbox credentials/token/binding. Its separate minimal settings module does not load database passwords, JWT signing secrets, Redis credentials, or intelligence-provider keys. Do not enable collection until mailbox access is authorized. No mail is sent by this workflow.

`POST /api/email/ingest` accepts only the scoped ingestion token and a previously collected `email_id`. It verifies the configured active owner UUID, exact mailbox, and collection binding; the token cannot authenticate normal user APIs or assign another owner. The operator's UUID binding—not an unverified address entered during registration—establishes authorization. Legacy manifests containing only `owner_email` are denied until the operator establishes their ownership independently.

Normal users use `POST /api/email/investigate`, `GET /api/email`, and `GET /api/email/{email_id}` with normal login authentication. List/detail/investigation verify owner UUID. Lists include subject, sender, timestamp, scan/status, and nested report. Parsed content is returned as JSON; consumers must render it as text, not active HTML.

The collector uses IMAP UIDs and `BODY.PEEK` to avoid marking failed deliveries as read. Failed ingestion stays pending. Message IDs are scoped by configured owner/mailbox and raw-message checksum. Collection is bounded to50MB/message, attachments to25MB. MIME attachment hashes use decoded bytes; temporary parser files are deleted. Actual saved attachments receive checksum verification and ClamAV scanning. Missing/error AV evidence remains unavailable.

The existing four-task email chord now finalizes into an owned Scan, canonical report, email report, Redis cache, and scoped WebSocket update. Missing evidence or a task failure produces `email_scan_unavailable`; success produces `email_scan_done`. Broker dispatch failure produces `email_dispatch_failed`. Root/email report directories carry `scan_id` for retention.

Email heuristic correlation is retained as `heuristic_score`/`heuristic_severity`; authoritative risk remains null/UNKNOWN while no validated final model exists. Every report retains `is_placeholder=true`, and no alert, incident, mail, or external notification is dispatched from these diagnostic paths. File/email semantic model validation and operator false-positive policy remain separate deployment work.

## Verification

`tests/test_file_email_workflows.py` executes real task functions against isolated payloads and SQLite, including cache identity, AV failure, payload tampering, macro metadata inspection, owner binding, duplicate ingestion, cross-user denial, finalization, and failure callbacks. Existing extension-cache/ClamAV regressions remain covered. `services/email/tests` are now offline parser/detector fixtures: importing or collecting them never opens IMAP or reads mailbox dumps.

Live authenticated API/Celery/ClamAV verification must be recorded after rebuilding workers/API; unit tests alone do not prove broker or container deployment behavior.


## Recovery and immutable attempts

A stale file/email job is marked `failed_timeout` by reconciliation and receives a durable null/UNKNOWN unavailable report before the database timeout is committed. Cache/WebSocket publication follows commit. Email list/detail prefer this canonical report. PostgreSQL row locks serialize reconciliation with finalizers, which cannot overwrite expired, cancelled, or already terminal outcomes. Duplicate ingestion/investigation returns the existing immutable attempt, including a failed attempt; it does not silently resurrect a timed-out run. Reanalysis requires a separately identified collection/analysis attempt rather than relabeling a frozen result. An upload can be submitted again to obtain a new owned Scan.

Only cache records bearing the complete `file_static_v10_v1` pipeline contract can skip asynchronous content inspection; older static-only records in the extension-sensitive v2 namespace are recomputed. Missing attachment antivirus evidence yields an unavailable email outcome, never a clean verdict.


## Email URL evidence contract

`email_url_diagnostics_v1` connects parser `content.extracted_urls` and `url_list.json` to the existing URL rules through SCYTHE's established offline URL feature helper. Canonical URL deduplication, scheme, literal-IP hosts, shortener syntax, URL length, and punycode syntax are observed locally; punycode is not proof of brand impersonation. Malformed/credential URLs retain unavailable status. Feed membership, domain age, typosquatting, redirect history, ASN/reputation, reverse DNS, and country comparisons remain null/unavailable unless independently collected by a provider. Missing DNSSEC evidence is not treated as a proven failure. No URL crawling, redirects, DNS, or intelligence-provider calls are introduced. These are heuristic diagnostics; final risk stays UNKNOWN.
