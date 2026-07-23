// background.js
// Manifest V3 service worker — the hub all other files talk to.
//
// Talks to:
//   popup.js            -> GET_SCAN_RESULT request/response
//   content.js / bdr.js -> BDR_EVENTS (telemetry) / BDR_CRITICAL (live threat)
//   warning.js           -> ALLOW_SITE (user chose "Continue Anyway")

const API_BASE_URL = "http://localhost:8000"; // TODO: update when deployed
const SCAN_ENDPOINT = `${API_BASE_URL}/api/scan`;
const RISK_BLOCK_THRESHOLD = 70;

const scanCache = new Map(); // tabId -> { url, result, timestamp }
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

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

      console.debug("[AEGIS] BDR_EVENTS merged for tab", tabId, existing);
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

      console.warn("[AEGIS] BDR_CRITICAL on tab", tabId, message.alert_type, message.details);

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

async function callBackendApi(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4000);

  try {
    const response = await fetch(SCAN_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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

/* ---------- Badge ---------- */

function updateBadge(tabId, riskScore) {
  let color = "#72b5ff";
  let text = "";

  if (riskScore >= RISK_BLOCK_THRESHOLD) {
    color = "#ff6b6b";
    text = "!";
  } else if (riskScore >= 30) {
    color = "#f5a623";
    text = "?";
  }

  // Wrap in try/catch — the tab may have closed between when the scan
  // started and when it finished (async), which otherwise throws an
  // uncaught "No tab with id" promise rejection.
  try {
    chrome.action.setBadgeBackgroundColor({ color, tabId }).catch(() => {});
    chrome.action.setBadgeText({ text, tabId }).catch(() => {});
  } catch {
    // tab gone, ignore
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
    console.warn("[AEGIS] Could not redirect tab to warning page:", err);
  }
}

/* ---------- Scan before navigation, block if the URL itself is risky ---------- */

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // main frame only
  const { tabId, url } = details;

  if (!/^https?:\/\//.test(url)) return;
  if (bypassedTabs.get(tabId) === url) return;

  // Fresh navigation — clear any stale runtime detections from the previous page.
  runtimeEvents.delete(tabId);

  const result = await scanUrl(url);
  scanCache.set(tabId, { url, result, timestamp: Date.now() });
  updateBadge(tabId, result.riskScore);

  if (result.riskScore >= RISK_BLOCK_THRESHOLD) {
    blockTabWithWarning(tabId, url, result);
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
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  scanCache.delete(tabId);
  bypassedTabs.delete(tabId);
  runtimeEvents.delete(tabId);
});

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