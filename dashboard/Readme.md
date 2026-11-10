# SCYTHE analyst dashboard

Compose mounts this directory read-only into Nginx at `/dashboard/`. Open
`https://localhost:8443/dashboard` for local configuration, or your deployment's
HTTPS origin. API calls use the same origin; no frontend package install or CDN
is required. Active pages load only `js/app.js` and `css/app.css`. The old mock,
common, radar and export scripts are inactive prototype assets.

## Workflow and availability

Sign in, submit a quick/full URL scan or a file up to 50 MB, then open its scan
ID. Reports poll while processing for up to five minutes and support manual
refresh. Recorded JSON, authenticated image previews, and inert text downloads
of captured HTML/HAR remain available. Hostile captured HTML never executes in
the dashboard. Email lists show only authorized ingested messages.

Missing or placeholder model outputs always show UNKNOWN. File heuristic
findings are distinguished from model probabilities. The UI does not activate
alerts, incidents, automatic decisions or a production model. Missing evidence
and unavailable providers are displayed explicitly.

Tokens and recently submitted scan IDs use this tab's session storage. Tokens
are cleared on 401 and revoked on sign-out. New tabs may require another sign-in;
report links preserve their destination. Cross-session history loads owned scan
records from the authenticated API with pagination. Local submissions remain
visible until returned by a history page. Aggregate incident statistics remain
unavailable and are not invented. Scores require the detailed report's model
availability contract and are not inferred from history metadata.

## Extension

Set `SCYTHE_ORIGIN` in `chrome-extension/config.js` to your HTTPS deployment and
reload the extension. Sign in on that origin, open Settings, and select
**Connect signed-in browser extension**. The bridge accepts only the exact
configured origin and `/dashboard/` path and acknowledges successful storage.
The popup offers a manual deep scan and opens its owned report. Missing model
scores remain UNKNOWN after local heuristics; server 401 removes expired tokens.
Disabling protection suppresses automatic navigation analysis and runtime
telemetry actions. A manually requested deep scan remains an explicit action.

Chrome MV3 navigation listeners are asynchronous observers: they cannot pause
navigation while an API scan runs. There is no guaranteed before-load protection
claim. A pre-navigation blocking policy would require a separate design.

## Verification

Run from the repository root, with Playwright/Chromium installed for Python:

```text
node scripts/test_extension_auth.cjs
python scripts/test_frontend_ui.py --origin https://localhost:8443
python scripts/test_extension_browser.py --origin https://localhost:8443 --extension chrome-extension
python scripts/frontend_workflow_smoke.py --origin https://localhost:8443 --url https://example.org/ --output workflow-ui.json
```

The first browser suite uses API fixtures. The second loads an actual temporary
unpacked extension with a disposable browser profile and fixture authentication.
The last exercises the real API, creates two disposable `.test` accounts and
benign URL/file scans, and checks cross-user ownership and logout revocation.
Its JSON lists account emails for administrative deactivation. Passwords and
tokens remain in memory. No real email is created and no notification is sent.
The sandbox image already includes Playwright/Chromium. Local self-signed TLS is
ignored only in test contexts; normal users require a trusted certificate.

Nginx renders `/tmp/scythe-nginx.conf` on startup; validate with
`nginx -c /tmp/scythe-nginx.conf -t`. `NGINX_HTTPS_PORT` is the externally
published TLS port (443 is omitted from redirect URLs). Redirects preserve path
and query. CSP allows no inline script/handler/style or external CDN.
