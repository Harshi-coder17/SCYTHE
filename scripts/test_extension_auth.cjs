"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const root = path.resolve(__dirname, "../chrome-extension");
function bridge(origin, pathname = "/dashboard/components/settings.html") {
  const state = { stored: {}, acknowledgements: [], listeners: [] };
  const context = { URL, location: { origin, pathname }, chrome: {
    storage: { local: { set: (data, done) => { state.stored = data; done(); }, remove: () => { state.stored = {}; } } }, runtime: {}
  } };
  context.window = { addEventListener: (_, listener) => state.listeners.push(listener), postMessage: (data, target) => state.acknowledgements.push({ data, target }) };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.join(root, "config.js"), "utf8"), context);
  vm.runInContext(fs.readFileSync(path.join(root, "auth-bridge.js"), "utf8"), context);
  state.send = (data, eventOrigin = origin, source = context.window) => state.listeners.forEach(listener => listener({ data, origin: eventOrigin, source }));
  return state;
}
const authorized = bridge("https://localhost:8443");
authorized.send({ type: "SCYTHE_AUTH_CONNECT", token: "header.payload.signature", email: "analyst@example.test" });
assert.equal(authorized.stored.scythe_token, "header.payload.signature");
assert.equal(authorized.acknowledgements.length, 1);
authorized.send({ type: "SCYTHE_AUTH_CONNECT", token: "malicious.payload.signature" }, "https://attacker.invalid");
assert.equal(authorized.stored.scythe_token, "header.payload.signature");
authorized.send({ type: "SCYTHE_AUTH_CONNECT", token: "invalid" });
assert.equal(authorized.stored.scythe_token, "header.payload.signature");
authorized.send({ type: "SCYTHE_AUTH_CLEAR" });
assert.equal(Object.keys(authorized.stored).length, 0);
assert.equal(bridge("https://attacker.invalid").listeners.length, 0);
assert.equal(bridge("https://localhost:8443", "/api/").listeners.length, 0);

// Service worker fixtures: unavailable backend + runtime observations must
// remain UNKNOWN. A local heuristic may never masquerade as a model score.
const listeners = [];
const listener = { addListener: handler => listeners.push(handler) };
const chrome = {
  runtime: { onMessage: listener, getURL: value => "chrome-extension://fixture/" + value },
  webNavigation: { onBeforeNavigate: listener },
  tabs: { onUpdated: listener, onRemoved: listener, onActivated: listener },
  storage: { local: { get: (_, done) => done({ scythe_token: "fixture" }) }, sync: { get: async () => ({}) } },
  action: { setBadgeText: async () => {}, setIcon: async () => {} }
};
const worker = { chrome, URL, URLSearchParams, console, AbortController, setTimeout, clearTimeout, setInterval, clearInterval, importScripts: () => {}, fetch: async () => ({ ok: true, json: async () => ({ risk_score: null, is_placeholder: false }) }) };
vm.createContext(worker);
vm.runInContext(fs.readFileSync(path.join(root, "config.js"), "utf8"), worker);
vm.runInContext(fs.readFileSync(path.join(root, "background.js"), "utf8"), worker);
const elements = new Map();
const popup = { URL, console, document: { addEventListener: () => {}, querySelectorAll: () => [], getElementById: id => {
  if (!elements.has(id)) elements.set(id, { textContent: "", style: {}, className: "", classList: { toggle: () => {} } });
  return elements.get(id);
} } };
vm.createContext(popup);
vm.runInContext(fs.readFileSync(path.join(root, "config.js"), "utf8"), popup);
vm.runInContext(fs.readFileSync(path.join(root, "popup.js"), "utf8"), popup);
popup.renderResult({ riskScore: null, isPlaceholder: true }, "example.org");
assert.equal(elements.get("heroStatusTitle").textContent, "VERDICT UNAVAILABLE");
assert.equal(elements.get("heroStatusBadge").textContent, "UNKNOWN");
assert.equal(elements.get("securityScoreText").textContent, "—");
(async () => {
  const missing = await worker.callBackendApi("https://example.org/");
  assert.equal(missing.riskScore, null);
  assert.equal(missing.isPlaceholder, true);
  assert.equal(missing.status, "Unknown");
  const fallback = worker.localHeuristicScan("https://example.org/");
  assert.equal(fallback.riskScore, null);
  assert.equal(fallback.isPlaceholder, true);
  vm.runInContext("runtimeEvents.set(9, {score: 80, indicators: ['fixture'], reasons: 'fixture'})", worker);
  const merged = await worker.handleGetScanResult({ tabId: 9, url: "https://example.org/" }, {});
  assert.equal(merged.riskScore, null);
  assert.equal(merged.status, "Unknown");
  let removed = false;
  chrome.storage.local.remove = () => { removed = true; };
  worker.fetch = async () => ({ ok: false, status: 401 });
  await assert.rejects(worker.callBackendApi("https://example.org/"), /401/);
  assert.equal(removed, true);
  chrome.storage.sync.get = (_, done) => done({ protectionDisabled: true });
  assert.equal(await worker.protectionEnabled(), false);
  const disabledReply = await new Promise(resolve => listeners[0]({ type: "BDR_CRITICAL", alert_type: "fixture" }, { tab: { id: 10, url: "https://example.org/" } }, resolve));
  assert.equal(disabledReply.disabled, true);
  assert.equal(vm.runInContext("runtimeEvents.has(10)", worker), false, "Disabled protection cannot act on runtime telemetry");
  chrome.storage.sync.get = (_, done) => done({ protectionDisabled: false });
  assert.equal(await worker.protectionEnabled(), true);

  let submitted = [];
  let screenshots = 0;
  worker.fetch = async (_, options) => {
    submitted.push(JSON.parse(options.body));
    return { ok: true, json: async () => ({ scan_id: "fixture-scan", job_id: "fixture-job" }) };
  };
  chrome.tabs.get = async () => ({ id: 9, windowId: 1, url: "https://example.org/" });
  chrome.tabs.query = async () => [];
  chrome.tabs.captureVisibleTab = async () => { screenshots += 1; return "data:image/png;base64,ZmFrZQ=="; };
  await worker.triggerStage2(9, "https://example.org/");
  assert.equal(screenshots, 0, "Inactive tabs cannot be screenshotted");
  assert.equal(submitted[0].screenshot_base64, "");
  worker.clearStage2Job(9);
  submitted = [];
  chrome.tabs.query = async () => [{ id: 9 }];
  chrome.scripting = { executeScript: async () => [{ result: { url: "https://different.example/", html: "wrong document" } }] };
  await worker.triggerStage2(9, "https://example.org/");
  assert.equal(submitted[0].screenshot_base64, "", "A stale document discards its screenshot");
  assert.equal(submitted[0].html, "");
  worker.clearStage2Job(9);
  submitted = [];
  chrome.scripting.executeScript = async () => [{ result: { url: "https://example.org/", html: "<html>fixture</html>" } }];
  const before = screenshots;
  await Promise.all([worker.triggerStage2(9, "https://example.org/"), worker.triggerStage2(9, "https://example.org/")]);
  assert.equal(screenshots - before, 1, "Concurrent requests coalesce");
  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].html, "<html>fixture</html>");
  submitted = [];
  vm.runInContext("stage2Jobs.get(9).startedAt = Date.now() - 11 * 60 * 1000", worker);
  await worker.triggerStage2(9, "https://example.org/");
  assert.equal(submitted.length, 1, "Expired job tracking does not prevent a new scan");
  vm.runInContext("scanCache.set(9, {url:'https://example.org/', result:{riskScore:88}, timestamp:Date.now()-6*60*1000})", worker);
  worker.fetch = async () => ({ ok: true, json: async () => ({ risk_score: null, is_placeholder: true }) });
  const expired = await worker.handleGetScanResult({ tabId: 9, url: "https://example.org/" }, {});
  assert.equal(expired.riskScore, null, "Expired scan scores cannot survive an unavailable refresh");
  console.log("Extension auth origin, missing-model, runtime merge, token expiry, protection toggle, stale/inactive document, coalescing and cache-expiry checks passed.");
})().catch(error => { console.error(error); process.exitCode = 1; });
