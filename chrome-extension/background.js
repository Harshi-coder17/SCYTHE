// background.js
// Manifest V3 service worker — the hub all other files talk to.
//
// Talks to:
//   popup.js            -> GET_SCAN_RESULT request/response
//   content.js / bdr.js -> BDR_EVENTS (telemetry) / BDR_CRITICAL (live threat)
//   warning.js           -> ALLOW_SITE (user chose "Continue Anyway")

// ── URL Configuration ─────────────────────────────────────────────────────────
// Edit config.js to change the backend URL — do NOT hardcode here.
// importScripts is the MV3-compatible way to load shared scripts in a SW.
try { importScripts("config.js"); } catch(e) { /* already loaded or unavailable */ }

const _API_BASE   = (typeof SCYTHE_CONFIG !== "undefined" ? SCYTHE_CONFIG.API_BASE_URL  : "http://localhost:8000");
const SCAN_ENDPOINT   = `${_API_BASE}/api/scans/quick`;
const STAGE2_ENDPOINT = `${_API_BASE}/api/scans/stage2`;

// ── Auth token helper ──────────────────────────────────────────────────────
// All /api/scans/* endpoints require a valid JWT Bearer token.
// Token is stored in chrome.storage.local by the dashboard login flow.
async function getAuthToken() {
  return new Promise((resolve) => {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      resolve(null);
      return;
    }
    chrome.storage.local.get(['scythe_token'], (result) => {
      resolve(result?.scythe_token || null);
    });
  });
}
const RISK_BLOCK_THRESHOLD = 70;
// Stage 2 (deep scan) is triggered when Quick Scan score >= this threshold.
// Keeps Stage 2 payload confined to genuinely suspicious pages.
const STAGE2_THRESHOLD = 40;

const scanCache    = new Map(); // tabId -> { url, result, timestamp }
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Tracks Stage 2 jobs in-flight: tabId -> { jobId, url, startedAt }
const stage2Jobs = new Map();

// tabId -> { score, indicators: [event_type,...], reasons }
// Populated live from content.js / bdr.js as they detect things.
const runtimeEvents = new Map();

const bypassedTabs = new Map(); // tabId -> url the user chose to proceed to anyway

/* ---------- Message listener (popup.js / content.js / bdr.js / warning.js) ---------- */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message?.type) {
    case "GET_SCAN_RESULT":
      handleGetScanResult(message, sender).then(sendResponse);
      return true; // async response

    case "BDR_EVENTS": {
      // Shape sent by content.js/bdr.js: { type: 'BDR_EVENTS', events: [{event_type, details, timestamp}, ...] }
      const tabId = sender.tab?.id;
      if (tabId == null) return false;

      const events = Array.isArray(message.events) ? message.events : [];
      if (events.length === 0) return false;

      const existing = runtimeEvents.get(tabId) || { score: 0, indicators: [], reasons: "" };

      events.forEach((ev) => {
        if (!existing.indicators.includes(ev.event_type)) {
          existing.indicators.push(ev.event_type);
        }
        existing.score = Math.min(100, existing.score + 8); // small bump per distinct event
      });

      existing.reasons = "Runtime behavioural analysis detected suspicious activity on this page.";
      runtimeEvents.set(tabId, existing);

      console.debug("[SCYTHE] BDR_EVENTS merged for tab", tabId, existing);
      return false;
    }

    case "BDR_CRITICAL": {
      // Shape sent by content.js/bdr.js: { type: 'BDR_CRITICAL', alert_type, details }
      const tabId = sender.tab?.id;
      const tabUrl = sender.tab?.url;
      if (tabId == null) return false;

      const existing = runtimeEvents.get(tabId) || { score: 0, indicators: [], reasons: "" };
      existing.score = 100;
      if (!existing.indicators.includes(message.alert_type)) {
        existing.indicators.push(message.alert_type);
      }
      existing.reasons = `Critical runtime threat detected: ${message.alert_type}`;
      runtimeEvents.set(tabId, existing);

      console.warn("[SCYTHE] BDR_CRITICAL on tab", tabId, message.alert_type, message.details);

      // Don't wait for the popup to be opened — block immediately.
      blockTabWithWarning(tabId, tabUrl, {
        riskScore: existing.score,
        status: "Blocked",
        reasons: existing.reasons,
        indicators: existing.indicators,
      });
      return false;
    }

    case "ALLOW_SITE":
      if (sender.tab?.id != null && message.url) {
        bypassedTabs.set(sender.tab.id, message.url);
      }
      sendResponse({ ok: true });
      return true;

    // ── V10 Stage 2: Manual trigger from popup.js ───────────────────────
    case "TRIGGER_STAGE2": {
      const tabId = message.tabId ?? sender.tab?.id;
      const url   = message.url;
      if (!tabId || !url) {
        sendResponse({ ok: false, error: "tabId and url are required" });
        return true;
      }
      triggerStage2(tabId, url)
        .then((result) => sendResponse({ ok: true, ...result }))
        .catch((err)  => sendResponse({ ok: false, error: err.message }));
      return true; // async response
    }

    // ── V10 Stage 2: Receive screenshot+DOM from content.js ────────────
    case "STAGE2_PAYLOAD": {
      const tabId = sender.tab?.id;
      const url   = sender.tab?.url;
      if (!tabId || !url) return false;
      const { screenshotBase64, html } = message;
      submitStage2Payload(tabId, url, screenshotBase64, html)
        .then(() => sendResponse({ ok: true }))
        .catch((err) => sendResponse({ ok: false, error: err.message }));
      return true;
    }

    default:
      return false;
  }
});

async function handleGetScanResult(message, sender) {
  const { tabId, url } = message;

  if (!url) {
    return { riskScore: 0, status: "Unknown", reasons: "No URL provided.", indicators: [] };
  }

  const cached = scanCache.get(tabId);
  if (cached && cached.url === url && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return cached.result;
  }

  const baseResult = await scanUrl(url);

  // Merge runtime detections from content.js / bdr.js, if any arrived for this tab.
  const runtime = runtimeEvents.get(tabId);
  let finalResult = { ...baseResult };

  if (runtime) {
    finalResult.riskScore = Math.min(100, baseResult.riskScore + runtime.score);
    finalResult.indicators = [...(baseResult.indicators || []), ...(runtime.indicators || [])];
    finalResult.reasons = `${baseResult.reasons} ${runtime.reasons}`.trim();
    finalResult.status =
      finalResult.riskScore >= RISK_BLOCK_THRESHOLD
        ? "Blocked"
        : finalResult.riskScore >= 30
        ? "Caution"
        : "Allowed";
  }

  scanCache.set(tabId, { url, result: finalResult, timestamp: Date.now() });
  updateBadge(tabId, finalResult.riskScore);

  return finalResult;
}

/* ---------- Scanning ---------- */

async function scanUrl(url) {
  try {
    const apiResult = await callBackendApi(url);
    if (apiResult) return apiResult;
  } catch (err) {
    console.warn("Backend scan failed, falling back to local heuristics:", err);
  }

  return localHeuristicScan(url);
}

/* ---------- V10 Stage 2 — Deep Scan (Screenshot + DOM → /api/analysis/stage2) ---------- */

/**
 * Capture a screenshot and DOM snapshot for the given tab and POST them to
 * the Stage 2 endpoint.  Returns { jobId } on success.
 *
 * Called automatically when Quick Scan score >= STAGE2_THRESHOLD, and
 * manually via the TRIGGER_STAGE2 message from popup.js.
 */
async function triggerStage2(tabId, url) {
  // Guard: only one Stage 2 job per tab at a time
  if (stage2Jobs.has(tabId)) {
    console.debug("[SCYTHE] Stage 2 already running for tab", tabId);
    return stage2Jobs.get(tabId);
  }

  console.info("[SCYTHE] Stage 2 triggered tab=", tabId, "url=", url);

  // 1. Capture screenshot via chrome.tabs.captureVisibleTab
  let screenshotBase64 = "";
  try {
    const tab = await chrome.tabs.get(tabId);
    const windowId = tab.windowId;
    const dataUrl  = await chrome.tabs.captureVisibleTab(windowId, { format: "png" });
    // Strip data URI header  ("data:image/png;base64,")
    screenshotBase64 = dataUrl.split(",")[1] ?? "";
  } catch (err) {
    console.warn("[SCYTHE] Screenshot capture failed:", err);
    // Continue — backend accepts empty screenshot but scores it lower
  }

  // 2. Inject content script to capture the live DOM snapshot
  let html = "";
  try {
    const [{ result: domHtml } = {}] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => document.documentElement.outerHTML,
    });
    html = domHtml ?? "";
  } catch (err) {
    console.warn("[SCYTHE] DOM capture failed:", err);
  }

  return submitStage2Payload(tabId, url, screenshotBase64, html);
}

/** POST screenshot + DOM to the backend Stage 2 endpoint. */
async function submitStage2Payload(tabId, url, screenshotBase64, html) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000); // 15 s

  const token = await getAuthToken();
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const resp = await fetch(STAGE2_ENDPOINT, {
      method:  "POST",
      headers,
      body: JSON.stringify({
        url,
        screenshot_base64: screenshotBase64,
        html: html,
        tab_id: tabId,
      }),
      signal: controller.signal,
    });

    if (!resp.ok) {
      const errText = await resp.text().catch(() => resp.statusText);
      throw new Error(`Stage 2 backend error ${resp.status}: ${errText}`);
    }

    const data = await resp.json();
    const jobRecord = {
      jobId:     data.job_id,
      scanId:    data.scan_id,
      url,
      startedAt: Date.now(),
    };

    stage2Jobs.set(tabId, jobRecord);
    console.info("[SCYTHE] Stage 2 queued job_id=", data.job_id, "scan_id=", data.scan_id);
    return jobRecord;

  } finally {
    clearTimeout(timeout);
  }
}

/** Clear Stage 2 job tracking when a tab navigates away or is closed. */
function clearStage2Job(tabId) {
  stage2Jobs.delete(tabId);
}

async function callBackendApi(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4000);

  const token = await getAuthToken();
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const response = await fetch(SCAN_ENDPOINT, {
      method: "POST",
      headers,
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    if (!response.ok) throw new Error(`API responded with ${response.status}`);

    const data = await response.json();

    return {
      riskScore: data.risk_score ?? data.riskScore ?? 0,
      status: data.status ?? (data.risk_score >= RISK_BLOCK_THRESHOLD ? "Blocked" : "Allowed"),
      reasons: data.reason ?? data.reasons ?? "",
      indicators: data.indicators ?? [],
      scannedAt: Date.now(),
    };
  } finally {
    clearTimeout(timeout);
  }
}

/* ---------- Local fallback heuristics ---------- */

function localHeuristicScan(url) {
  let score = 0;
  const indicators = [];
  let hostname = "";
  let pathname = "";

  try {
    const parsed = new URL(url);
    hostname = parsed.hostname;
    pathname = parsed.pathname;
  } catch {
    return {
      riskScore: 0,
      status: "Unknown",
      reasons: "Could not parse URL.",
      indicators: [],
      scannedAt: Date.now(),
    };
  }

  // 1. Phishing Simulation & Testing check
  if (
    hostname.includes("testsafebrowsing") || 
    hostname.includes("safebrowsing") || 
    pathname.includes("phishing.html") || 
    pathname.includes("phishing")
  ) {
    score += 90;
    indicators.push("URL matches known phishing test domain/signature");
  }

  if (url.startsWith("http://")) {
    score += 25;
    indicators.push("Connection is not encrypted (HTTP)");
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 30;
    indicators.push("Uses a raw IP address instead of a domain");
  }

  const subdomainCount = hostname.split(".").length - 2;
  if (subdomainCount > 2) {
    score += 15;
    indicators.push("Unusually high number of subdomains");
  }

  const suspiciousWords = ["login", "verify", "secure", "account", "update", "confirm", "signin", "phish"];
  const wordHits = suspiciousWords.filter((w) => hostname.toLowerCase().includes(w) || pathname.toLowerCase().includes(w));
  if (wordHits.length > 0) {
    score += 20;
    indicators.push(`URL contains suspicious keyword(s): ${wordHits.join(", ")}`);
  }

  if ((hostname.match(/-/g) || []).length >= 2) {
    score += 15;
    indicators.push("Domain uses multiple hyphens, common in spoofed URLs");
  }

  if (hostname.length > 40) {
    score += 10;
    indicators.push("Unusually long domain name");
  }

  score = Math.min(score, 100);

  const status = score >= RISK_BLOCK_THRESHOLD ? "Blocked" : score >= 30 ? "Caution" : "Allowed";
  const reasons =
    indicators.length > 0
      ? "Local heuristic scan found characteristics associated with risky or deceptive sites."
      : "No suspicious characteristics found by local heuristic scan.";

  return { riskScore: score, status, reasons, indicators, scannedAt: Date.now() };
}

/* ---------- Dynamic Icon + Pulsating Alert System ---------- */

// Icon paths keyed by threat level
const ICONS = {
  default: { 16: "icons/default_logo_16.png", 32: "icons/default_logo_32.png", 48: "icons/default_logo_48.png", 128: "icons/default_logo_128.png" },
  safe:    { 16: "icons/green_logo_16.png",   32: "icons/green_logo_32.png",   48: "icons/green_logo_48.png",   128: "icons/green_logo_128.png"   },
  warn:    { 16: "icons/orange_logo_16.png",  32: "icons/orange_logo_32.png",  48: "icons/orange_logo_48.png",  128: "icons/orange_logo_128.png"  },
  danger:  { 16: "icons/red_logo_16.png",     32: "icons/red_logo_32.png",     48: "icons/red_logo_48.png",     128: "icons/red_logo_128.png"     },
};

// Track pulsation intervals: tabId -> intervalId
const pulseIntervals = new Map();
// Track whether this tab's pulse has been dismissed by clicking the extension icon
const pulseDismissed = new Map(); // tabId -> bool

/**
 * Set the extension icon for a specific tab.
 * Uses chrome.action.setIcon with the path map.
 */
function setTabIcon(tabId, level) {
  const paths = ICONS[level] || ICONS.default;
  try {
    chrome.action.setIcon({ path: paths, tabId }).catch(() => {});
  } catch { /* tab gone */ }
}

/**
 * Draw a pulsating glow ring around the logo on an offscreen canvas
 * and push it to the action icon, creating a real animation effect.
 *
 * The pulse is redrawn every 40ms (25 fps) using a sine wave to smoothly
 * animate the glow radius and opacity.
 */
async function startPulseAnimation(tabId, level) {
  // Stop any existing pulse on this tab first
  stopPulseAnimation(tabId);

  // Reset dismissed flag when a new threat is detected
  pulseDismissed.set(tabId, false);

  const size = 32; // Canvas size — Chrome uses 32px for toolbar
  const imgPath = ICONS[level]?.[32] || ICONS.default[32];

  // Fetch the base logo image as a blob and decode it
  let imageBitmap;
  try {
    const resp = await fetch(chrome.runtime.getURL(imgPath));
    const blob = await resp.blob();
    imageBitmap = await createImageBitmap(blob);
  } catch (e) {
    // Fallback: just set the icon statically
    setTabIcon(tabId, level);
    return;
  }

  let frame = 0;
  // Glow color depending on level
  const glowColor = level === "danger" ? "255,40,40" : "255,140,0";

  const intervalId = setInterval(() => {
    // If tab is gone or dismissed, stop
    if (pulseDismissed.get(tabId)) {
      stopPulseAnimation(tabId);
      setTabIcon(tabId, level); // keep correct icon, just no pulse
      return;
    }

    // Sine wave: 0→1→0 over 60 frames (~2.4 s period at 25 fps)
    const t = Math.sin((frame / 60) * Math.PI);
    frame = (frame + 1) % 120;

    const glowOpacity  = 0.3 + 0.7 * t;          // 0.3–1.0
    const glowRadius   = 2 + 5 * t;              // 2–7 px spread
    const glowBlur     = 1 + 4 * t;              // 1–5 px blur

    // Draw onto offscreen canvas
    const canvas = new OffscreenCanvas(size, size);
    const ctx    = canvas.getContext("2d");

    // Clear
    ctx.clearRect(0, 0, size, size);

    // Draw glow ring (before logo so it appears behind)
    ctx.save();
    ctx.shadowColor  = `rgba(${glowColor},${glowOpacity.toFixed(2)})`;
    ctx.shadowBlur   = glowBlur * 4;
    ctx.beginPath();
    ctx.arc(size / 2, size / 2, size / 2 - glowRadius, 0, Math.PI * 2);
    ctx.strokeStyle = `rgba(${glowColor},${(glowOpacity * 0.8).toFixed(2)})`;
    ctx.lineWidth   = glowRadius * 1.5;
    ctx.stroke();
    ctx.restore();

    // Draw the base logo on top
    ctx.drawImage(imageBitmap, 0, 0, size, size);

    // Convert to ImageData and push to Chrome
    const imageData = ctx.getImageData(0, 0, size, size);
    chrome.action.setIcon({ imageData: { 32: imageData }, tabId }).catch(() => {
      stopPulseAnimation(tabId);
    });
  }, 40); // 25 fps

  pulseIntervals.set(tabId, intervalId);
}

/** Stop and clear a pulsation animation for a tab. */
function stopPulseAnimation(tabId) {
  const id = pulseIntervals.get(tabId);
  if (id != null) {
    clearInterval(id);
    pulseIntervals.delete(tabId);
  }
}

/**
 * Main icon update entry point — called after every scan result.
 *
 * Risk levels (mirrors architecture thresholds):
 *   score < STAGE2_THRESHOLD (40)   → safe    → green logo
 *   score 40–69                      → warn    → orange logo + pulse
 *   score >= RISK_BLOCK_THRESHOLD(70)→ danger  → red logo + pulse
 *   no scan yet / non-http page      → default → default logo
 */
function updateBadge(tabId, riskScore) {
  let level;

  if (riskScore === null || riskScore === undefined) {
    level = "default";
  } else if (riskScore >= RISK_BLOCK_THRESHOLD) {
    level = "danger";
  } else if (riskScore >= STAGE2_THRESHOLD) {
    level = "warn";
  } else {
    level = "safe";
  }

  // Clear old text badge (we use icon colour instead)
  try {
    chrome.action.setBadgeText({ text: "", tabId }).catch(() => {});
  } catch { /* tab gone */ }

  if (level === "danger" || level === "warn") {
    // Kick off pulsating glow animation
    startPulseAnimation(tabId, level);
  } else {
    // No pulse needed — stop any running one and set icon immediately
    stopPulseAnimation(tabId);
    pulseDismissed.delete(tabId);
    setTabIcon(tabId, level);
  }
}

/** Called when the user clicks the extension icon (opens popup). Dismisses pulse. */
function dismissPulseForTab(tabId) {
  if (pulseIntervals.has(tabId)) {
    pulseDismissed.set(tabId, true); // interval will clean itself up on next tick
  }
}

/* ---------- Block risky tabs by redirecting to warning.html ---------- */

async function blockTabWithWarning(tabId, url, result) {
  if (tabId == null || !url) return;
  if (url.startsWith(chrome.runtime.getURL(""))) return; // don't block our own pages
  if (bypassedTabs.get(tabId) === url) return; // user already chose to continue here

  // The tab may have closed or navigated elsewhere by the time an async
  // scan finishes — verify it still exists before touching it.
  try {
    await chrome.tabs.get(tabId);
  } catch {
    return; // tab is gone, nothing to block
  }

  const params = new URLSearchParams({
    url,
    score: String(result.riskScore ?? 0),
    severity: result.status ?? "Blocked",
    explanation: result.reasons ?? "",
    indicators: encodeURIComponent(JSON.stringify(result.indicators ?? [])),
  });

  try {
    await chrome.tabs.update(tabId, {
      url: chrome.runtime.getURL(`warning.html?${params.toString()}`),
    });
  } catch (err) {
    console.warn("[SCYTHE] Could not redirect tab to warning page:", err);
  }
}

/* ---------- Scan before navigation, block if the URL itself is risky ---------- */

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // main frame only
  const { tabId, url } = details;

  if (!/^https?:\/\//.test(url)) return;
  if (bypassedTabs.get(tabId) === url) return;

  // Fresh navigation — clear any stale runtime detections and Stage 2 jobs
  // from the previous page.
  runtimeEvents.delete(tabId);
  clearStage2Job(tabId);

  const result = await scanUrl(url);
  scanCache.set(tabId, { url, result, timestamp: Date.now() });
  updateBadge(tabId, result.riskScore);

  if (result.riskScore >= RISK_BLOCK_THRESHOLD) {
    blockTabWithWarning(tabId, url, result);
  }

  // ── V10: Trigger Stage 2 for suspicious pages (non-blocking) ────────
  // Score between STAGE2_THRESHOLD and RISK_BLOCK_THRESHOLD: suspicious
  // but not blocked — start deep analysis in the background.
  if (result.riskScore >= STAGE2_THRESHOLD && result.riskScore < RISK_BLOCK_THRESHOLD) {
    triggerStage2(tabId, url).catch((err) =>
      console.warn("[SCYTHE] Stage 2 dispatch failed:", err)
    );
  }
});

/* ---------- Auto-scan on load complete (badge stays fresh even without a nav event) ---------- */

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && /^https?:\/\//.test(tab.url)) {
    const cached = scanCache.get(tabId);
    const alreadyScanned = cached && cached.url === tab.url && Date.now() - cached.timestamp < CACHE_TTL_MS;

    if (!alreadyScanned) {
      scanUrl(tab.url).then((result) => {
        scanCache.set(tabId, { url: tab.url, result, timestamp: Date.now() });
        updateBadge(tabId, result.riskScore);
      });
    } else {
      updateBadge(tabId, cached.result.riskScore);
    }

    detectAndSyncTheme(tabId);
  } else if (changeInfo.status === "complete" && tab.url && !/^https?:\/\//.test(tab.url)) {
    // Non-scannable page (chrome://, about:, file://, etc.) — reset to default icon
    stopPulseAnimation(tabId);
    pulseDismissed.delete(tabId);
    setTabIcon(tabId, "default");
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  scanCache.delete(tabId);
  bypassedTabs.delete(tabId);
  runtimeEvents.delete(tabId);
  stopPulseAnimation(tabId);
  pulseDismissed.delete(tabId);
  clearStage2Job(tabId);  // V10: clean up Stage 2 job tracking
});

/* ---------- Dismiss pulse when user opens the popup ---------- */
// chrome.action.onClicked fires only when there is NO popup set.
// Since we have a popup, we intercept the POPUP_OPENED message sent by popup.js instead.
// As a belt-and-suspenders measure, we also hook onActivated so switching to the tab
// after the popup is closed eventually resets the pulse state.
chromeRuntime_onMessage_addPulseHandler(); // defined below

function chromeRuntime_onMessage_addPulseHandler() {
  // Injected after the main onMessage listener so we don't duplicate the switch block.
  // popup.js sends { type: "POPUP_OPENED", tabId } as its first action on DOMContentLoaded.
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === "POPUP_OPENED" && message.tabId != null) {
      dismissPulseForTab(message.tabId);
      sendResponse({ ok: true });
      return true;
    }
  });
}

/* ---------- Theme sync: match popup/warning theme to the site's theme ---------- */

function readPageColorScheme() {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

async function detectAndSyncTheme(tabId) {
  try {
    const [{ result: theme } = {}] = await chrome.scripting.executeScript({
      target: { tabId },
      func: readPageColorScheme,
    });

    if (!theme) return;

    const stored = await chrome.storage.sync.get(["theme"]);
    if (stored.theme === theme) return;

    await chrome.storage.sync.set({ theme });

    chrome.runtime.sendMessage({ type: "THEME_CHANGED", theme }).catch(() => {});
  } catch (err) {
    // Fails silently on restricted pages (chrome://, Web Store, etc.)
  }
}

chrome.tabs.onActivated.addListener(({ tabId }) => {
  detectAndSyncTheme(tabId);
});