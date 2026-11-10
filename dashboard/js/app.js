/* Production UI: same-origin authenticated API calls; no mock verdicts. */
"use strict";
const API = "/api";
const TOKEN_KEY = "scythe_token";
const page = document.body.dataset.page;
const app = document.getElementById("app");
let polling = null;
let objectUrls = [];
const token = () => sessionStorage.getItem(TOKEN_KEY);
const uuid = value => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

function node(tag, text, cls) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (cls) element.className = cls;
  return element;
}
function notice(message, error = false) {
  const element = document.getElementById("notice");
  element.textContent = message;
  element.className = error ? "error" : "success";
}
function button(text, action) {
  const element = node("button", text);
  element.type = "button";
  element.addEventListener("click", action);
  return element;
}
function heading(title, description) {
  app.append(node("h1", title));
  if (description) app.append(node("p", description, "muted"));
}
function field(label, type, name, required = true) {
  const wrapper = node("label", label);
  const input = node("input");
  Object.assign(input, { type, name, required });
  wrapper.append(input);
  return wrapper;
}
async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (token()) headers.set("Authorization", `Bearer ${token()}`);
  const response = await fetch(API + path, { ...options, headers, credentials: "omit", cache: "no-store" });
  if (response.status === 401) {
    clearSession();
    throw new Error("Your session is unavailable or expired. Sign in again.");
  }
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(typeof detail.detail === "string" ? detail.detail : `Request failed (${response.status}).`);
  }
  if (response.status === 204) return null;
  return options.blob ? response.blob() : response.json();
}
function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem("scythe_email");
  sessionStorage.removeItem("scythe_recent_scans");
  window.postMessage({ type: "SCYTHE_AUTH_CLEAR" }, location.origin);
  updateSession();
}
function updateSession() {
  document.getElementById("session").textContent = token() ? `Signed in as ${sessionStorage.getItem("scythe_email") || "analyst"}` : "Not signed in";
  document.getElementById("auth-link").textContent = token() ? "Account" : "Sign in";
}
function remember(id) {
  if (!uuid(id)) return;
  const recent = JSON.parse(sessionStorage.getItem("scythe_recent_scans") || "[]");
  sessionStorage.setItem("scythe_recent_scans", JSON.stringify([id, ...recent.filter(item => item !== id)].slice(0, 30)));
}
function reportLink(id) {
  const link = node("a", id);
  link.href = `report.html?scan_id=${encodeURIComponent(id)}`;
  return link;
}
function details(value, title = "Recorded report") {
  const wrapper = node("details");
  wrapper.append(node("summary", title), node("pre", JSON.stringify(value, null, 2)));
  return wrapper;
}
function verdict(report) {
  const score = report.risk_score ?? report.score;
  const unavailable = report.is_placeholder === true || typeof score !== "number" || !Number.isFinite(score);
  const wrapper = node("div", undefined, "card");
  wrapper.append(node("p", unavailable ? "UNKNOWN · model verdict unavailable" : `${report.risk_level || report.severity || "Recorded score"} · ${score}`, "status"));
  if (unavailable) wrapper.append(node("p", "This result cannot establish that the URL or file is safe. Inspect the available evidence."));
  if (report.heuristic_only) wrapper.append(node("p", "Heuristic file findings only; this is not a validated model probability.", "muted"));
  if (Array.isArray(report.reasons)) {
    const list = node("ul"); report.reasons.forEach(reason => list.append(node("li", String(reason)))); wrapper.append(list);
  }
  return wrapper;
}
async function guarded(operation, submit) {
  if (submit) submit.disabled = true;
  notice("");
  try { await operation(); } catch (error) { notice(error.message || "Request unavailable.", true); }
  finally { if (submit) submit.disabled = false; }
}
function authPage() {
  heading("Analyst account", "Sign in to submit scans and retrieve your own evidence.");
  const form = node("form", undefined, "card");
  const email = field("Email", "email", "email");
  const password = field("Password", "password", "password");
  email.lastChild.autocomplete = "username";
  password.lastChild.autocomplete = "current-password";
  const submit = node("button", "Sign in"); submit.type = "submit";
  form.append(email, password, submit);
  form.addEventListener("submit", event => { event.preventDefault(); guarded(async () => {
    const data = new FormData(form);
    const result = await request("/auth/login", { method: "POST", body: new URLSearchParams({ username: data.get("email"), password: data.get("password") }) });
    if (!result.access_token) throw new Error("Authentication returned no token.");
    // A successful account switch cannot inherit another account's pending
    // scan IDs or extension session, even when Sign out was skipped.
    clearSession();
    sessionStorage.setItem(TOKEN_KEY, result.access_token);
    sessionStorage.setItem("scythe_email", String(data.get("email")));
    password.lastChild.value = "";
    updateSession(); notice("Signed in. Open New scan, or connect the extension from Settings.");
    const next = new URLSearchParams(location.search).get("next");
    if (next) {
      const destination = new URL(next, location.origin);
      if (destination.origin === location.origin && /^\/dashboard\/components\/(dashboard|scan|report|email|settings)\.html$/.test(destination.pathname)) location.assign(destination.href);
    }
  }, submit); });
  form.append(button("Create account", () => guarded(async () => {
    if (!form.reportValidity()) return;
    const result = await request("/auth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(form))) });
    notice(result.message || "Registration accepted. You may now attempt to sign in.");
  })));
  form.append(node("p", "New passwords need at least 12 characters, upper/lowercase, a digit and a symbol. Common or breached passwords are rejected.", "muted"));
  app.append(form);
}
function dashboardPage() {
  heading("Your scan workspace", "Only authenticated server results are shown. No sample incidents or confidence values are included.");
  const recent = JSON.parse(sessionStorage.getItem("scythe_recent_scans") || "[]").filter(uuid);
  app.append(node("h2", "Your scan history"));
  const output = node("section");
  let nextOffset = 0;
  let historyAvailable = null;
  const records = new Map();
  const more = button("Load more scans", () => guarded(() => load(false), more));
  more.hidden = true;
  function render() {
    output.replaceChildren();
    const pending = recent.filter(id => !records.has(id));
    if (!records.size && !pending.length) output.append(node("p", historyAvailable === true ? "No owned scans are available. Submit a scan to start your history." : historyAvailable === false ? "Server scan history is currently unavailable. Refresh to retry." : "Loading your owned scan history…", "muted"));
    pending.forEach(id => {
      const row = node("div", undefined, "card");
      row.append(reportLink(id), node("p", "Submitted in this session; not yet returned by the current history page.", "muted"));
      output.append(row);
    });
    records.forEach(record => {
      const row = node("div", undefined, "card");
      row.append(reportLink(record.scan_id), node("p", record.url || "File or email scan"));
      row.append(node("p", `Status: ${record.status || "unavailable"}`, "badge"));
      row.append(node("p", record.created_at ? `Created: ${record.created_at}` : "Creation timestamp unavailable", "muted"));
      // History metadata does not attest model availability. Scores are shown
      // only in the detailed report where its placeholder contract is known.
      output.append(row);
    });
    more.hidden = nextOffset === null || historyAvailable !== true;
  }
  async function load(reset) {
    const offset = reset ? 0 : nextOffset;
    if (offset === null) return;
    let data;
    try { data = await request(`/scans?limit=50&offset=${offset}`); }
    catch (error) { historyAvailable = false; render(); throw error; }
    if (!Array.isArray(data.items)) { historyAvailable = false; render(); throw new Error("Scan history returned an invalid response."); }
    historyAvailable = true;
    if (reset) records.clear();
    data.items.forEach(record => { if (uuid(record.scan_id)) records.set(record.scan_id, record); });
    nextOffset = Number.isInteger(data.next_offset) && data.next_offset > offset && data.next_offset <= 10000 ? data.next_offset : null;
    render();
  }
  app.append(button("Refresh history", () => guarded(() => load(true))), output, more);
  app.append(node("p", "History contains scans owned by this account. Aggregate incident statistics remain unavailable.", "muted"));
  render();
  guarded(() => load(true));
}
function scanPage() {
  heading("New scan", "Quick URL checks or a full server capture and sandbox workflow. File uploads are limited to 50 MB.");
  const form = node("form", undefined, "card");
  const url = field("URL", "url", "url"); url.lastChild.placeholder = "https://example.org/";
  const label = node("label", "URL scan mode"); const mode = node("select"); mode.name = "mode";
  [["quick", "Quick URL check"], ["full", "Full capture and sandbox scan"]].forEach(([value, text]) => { const option = node("option", text); option.value = value; mode.append(option); });
  label.append(mode); const submit = node("button", "Scan URL"); submit.type = "submit"; form.append(url, label, submit);
  const output = node("section");
  form.addEventListener("submit", event => { event.preventDefault(); guarded(async () => {
    const parsed = new URL(url.lastChild.value);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error("Use an HTTP(S) URL without embedded credentials.");
    const result = await request(`/scans/${mode.value}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: parsed.href }) });
    output.replaceChildren(verdict(result), details(result));
    if (result.scan_id) { remember(result.scan_id); output.append(reportLink(result.scan_id)); }
    notice(result.scan_id ? "Scan queued. Open its report for progress and evidence." : "Quick check completed; inspect availability before interpreting the result.");
  }, submit); });
  const files = node("form", undefined, "card"); const upload = field("Choose a file", "file", "file");
  const fileSubmit = node("button", "Scan file"); fileSubmit.type = "submit"; files.append(upload, fileSubmit);
  files.addEventListener("submit", event => { event.preventDefault(); guarded(async () => {
    const file = upload.lastChild.files[0];
    if (!file || file.size > 50 * 1024 * 1024) throw new Error("Choose a file up to 50 MB.");
    const result = await request("/scans/file", { method: "POST", body: new FormData(files) });
    output.replaceChildren(details(result, "File scan submission"));
    if (result.scan_id) { remember(result.scan_id); output.append(reportLink(result.scan_id)); }
    notice("File submitted. Open its report to inspect completion status and recorded findings.");
  }, fileSubmit); });
  app.append(form, files, output);
}
function reportPage() {
  heading("Scan evidence", "Retrieve a scan that belongs to your account. Missing artifacts remain unavailable.");
  const form = node("form", undefined, "card"); const id = field("Scan ID", "text", "scan_id");
  id.lastChild.value = new URLSearchParams(location.search).get("scan_id") || new URLSearchParams(location.search).get("id") || "";
  const submit = node("button", "Load report"); submit.type = "submit"; form.append(id, submit);
  const output = node("section"); const evidence = node("section"); const preview = node("section");
  const artifacts = ["browser.png", "sandbox.png", "sandbox_fullpage.png", "browser.html", "sandbox.html", "risk_report.json", "browser_features.json", "consistency_report.json", "sandbox_metadata.json", "ece_report.json", "network.har"];
  let refreshCount = 0;
  async function load() {
    const value = id.lastChild.value.trim();
    if (!uuid(value)) throw new Error("Enter a valid UUID scan ID.");
    const data = await request(`/scans/${value}`); remember(value);
    clearInterval(polling);
    if (!data.risk_report && !/failed|unavailable|done|complete/i.test(data.status || "") && refreshCount < 60) {
      polling = setTimeout(() => { refreshCount += 1; guarded(load); }, 5000);
    }
    output.replaceChildren(node("p", `Status: ${data.status || "unavailable"}`, "badge"), node("p", data.url || "File scan"), verdict(data.risk_report || data), details(data));
    if (!data.risk_report) output.append(node("p", "A final risk report is not available yet. Refresh while the scan is processing.", "muted"));
    evidence.replaceChildren(node("h2", "Available evidence"), node("p", "Select an artifact to retrieve it with your authenticated session. A missing artifact is reported explicitly.", "muted"));
    const actions = node("div", undefined, "actions");
    artifacts.forEach(name => actions.append(button(name, () => guarded(async () => {
      const blob = await request(`/scans/${value}/artifacts/${name}`, { blob: true });
      preview.replaceChildren(node("h2", name));
      if (name.endsWith(".png")) {
        const url = URL.createObjectURL(blob); objectUrls.push(url);
        const image = node("img"); image.src = url; image.alt = name; image.className = "evidence"; preview.append(image);
      } else if (name.endsWith(".json")) preview.append(node("pre", await blob.text()));
      else {
        // Never execute captured hostile HTML inside the dashboard origin.
        const safeBlob = new Blob([await blob.text()], { type: "text/plain" });
        const url = URL.createObjectURL(safeBlob); objectUrls.push(url);
        const link = node("a", "Download captured evidence as text"); link.href = url; link.download = name + ".txt"; preview.append(link);
      }
      notice("Artifact loaded.");
    }))));
    evidence.append(actions);
  }
  form.addEventListener("submit", event => { event.preventDefault(); guarded(load, submit); });
  app.append(form, output, evidence, preview);
  app.append(button("Refresh status", () => guarded(load)));
  if (id.lastChild.value) guarded(load, submit);
}
function emailPage() {
  heading("Mailbox investigations", "Only messages authorized for your account appear here. Mailbox ingestion must be configured by an administrator.");
  const output = node("section");
  async function load() {
    const data = await request("/email"); output.replaceChildren();
    if (!data.emails?.length) output.append(node("p", "No authorized ingested emails are available.", "muted"));
    (data.emails || []).forEach(email => {
      const card = node("div", undefined, "card"); card.append(node("h2", email.subject || "No subject"), node("p", email.from_address || "Sender unavailable"), node("p", `Status: ${email.status || "unavailable"}`));
      if (email.risk_report) card.append(verdict(email.risk_report));
      card.append(button("View recorded evidence", () => guarded(async () => {
        const detail = await request(`/email/${encodeURIComponent(email.email_id)}`); card.append(details(detail, "Email evidence"));
      })));
      card.append(button("Investigate", () => guarded(async () => {
        const result = await request("/email/investigate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email_id: email.email_id }) });
        notice(`Investigation queued: ${result.email_id}. Refresh to inspect completion.`);
      })));
      if (email.scan_id && uuid(email.scan_id)) card.append(reportLink(email.scan_id));
      output.append(card);
    });
  }
  app.append(button("Refresh mailbox", () => guarded(load)), output); guarded(load);
}
function settingsPage() {
  heading("Local settings", "The dashboard uses this HTTPS origin. Operational policies and model configuration are managed on the server.");
  app.append(node("p", `API origin: ${location.origin}`));
  app.append(node("p", "Authentication is kept in this tab's session storage. No security policy or incident threshold is changed by this page.", "muted"));
  app.append(button("Connect signed-in browser extension", () => {
    if (!token()) { notice("Sign in first.", true); return; }
    let acknowledged = false;
    const listener = event => {
      if (event.source !== window || event.origin !== location.origin || event.data?.type !== "SCYTHE_AUTH_CONNECTED") return;
      acknowledged = true; window.removeEventListener("message", listener); notice("Extension session connected.");
    };
    window.addEventListener("message", listener);
    window.postMessage({ type: "SCYTHE_AUTH_CONNECT", token: token(), email: sessionStorage.getItem("scythe_email") }, location.origin);
    setTimeout(() => { window.removeEventListener("message", listener); if (!acknowledged) notice("No extension acknowledgement. Install or reload the extension, and configure its origin to match this page.", true); }, 2000);
  }));
  app.append(button("Sign out and revoke token", () => guarded(async () => {
    await request("/auth/logout", { method: "POST" }); clearSession(); notice("Signed out; the server token was revoked.");
  })));
}
// Retire persistent dashboard credentials from the previous mock prototype.
localStorage.removeItem(TOKEN_KEY);
localStorage.removeItem("scythe_email");
updateSession();
if (page !== "auth" && page !== "home" && !token()) {
  heading("Sign in required", "Sign in before submitting scans or viewing private reports.");
  const link = node("a", "Open sign in"); link.href = "auth.html?next=" + encodeURIComponent(location.pathname + location.search); app.append(link);
} else ({ auth: authPage, home: () => { heading("SCYTHE", "Inspect URL, file and email evidence through your authenticated analyst workspace."); const link = node("a", "Open dashboard"); link.href = "dashboard.html"; app.append(link); }, dashboard: dashboardPage, scan: scanPage, report: reportPage, email: emailPage, settings: settingsPage }[page] || dashboardPage)();
window.addEventListener("pagehide", () => { clearInterval(polling); objectUrls.forEach(url => URL.revokeObjectURL(url)); });
// Browser back/forward snapshots must re-check session state instead of
// restoring private report DOM after sign-out or an account switch.
window.addEventListener("pageshow", event => { if (event.persisted) location.reload(); });
