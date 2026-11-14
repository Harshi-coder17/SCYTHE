function getGridItem(el) {
  if (!el) return null;
  if (typeof el.closest === "function") return getGridItem(el);
  return el.parentElement || null;
}
// popup.js
// Logic for the extension's popup.html — pulls scan data for the active tab,
// renders it into the UI, and wires up the action buttons, theme toggle, and live protection.

// Read dashboard URL from config.js (loaded as a <script> tag in popup.html)
const DASHBOARD_URL = (typeof SCYTHE_CONFIG !== "undefined")
  ? SCYTHE_CONFIG.DASHBOARD_URL
  : "https://localhost:8443/dashboard/components/dashboard.html";

document.addEventListener("DOMContentLoaded", init);

async function init() {
  applyStoredTheme();
  wireThemeToggle();
  wireProtectionSwitch();

  const tab = await getActiveTab();
  if (!tab) {
    renderError("Unable to read the active tab.");
    return;
  }

  // ── Dismiss pulsating alert as soon as the user opens the popup ──────────
  // The background service worker is animating the icon for this tab.
  // Now that the user clicked the extension icon, we stop the pulse.
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
    try {
      const p = chrome.runtime.sendMessage({ type: "POPUP_OPENED", tabId: tab.id });
      if (p && typeof p.catch === "function") p.catch(() => {});
    } catch {}
  }

  // Display URL in top hero card & grid
  const hostname = safeHostname(tab.url);
  const heroUrlEl = document.getElementById("heroUrl");
  const gridSiteEl = document.getElementById("gridSiteUrl");
  if (heroUrlEl) {
    heroUrlEl.textContent = hostname;
    heroUrlEl.title = tab.url || hostname;
  }
  if (gridSiteEl) {
    gridSiteEl.textContent = hostname;
    gridSiteEl.title = tab.url || hostname;
  }

  // Pre-populate SSL status directly from tab URL
  const isHttpsInit = tab.url ? tab.url.startsWith("https://") : true;
  const isHttpInit = tab.url ? tab.url.startsWith("http://") : false;
  const isInternalInit = tab.url ? (tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://") || tab.url.startsWith("about:") || tab.url.startsWith("file://")) : false;
  const initSSL = document.getElementById("gridSSLStatus");
  if (initSSL) {
    if (isHttpInit) {
      initSSL.textContent = "Unencrypted (HTTP)";
      initSSL.title = "Unencrypted plain HTTP connection (Insecure)";
      const item = getGridItem(initSSL);
      if (item) item.className = "grid-item blocked";
    } else if (isInternalInit) {
      initSSL.textContent = "Internal Page";
      initSSL.title = "Local or browser internal page";
      const item = getGridItem(initSSL);
      if (item) item.className = "grid-item";
    } else {
      initSSL.textContent = "Encrypted (HTTPS)";
      initSSL.title = "Verified HTTPS SSL/TLS encryption";
      const item = getGridItem(initSSL);
      if (item) item.className = "grid-item allowed";
    }
  }

  try {
    // Ask the background/service worker for the scan result of this tab.
    const result = await sendMessage({ type: "GET_SCAN_RESULT", tabId: tab.id, url: tab.url });

    renderResult(result, hostname, tab.url);
  } catch (err) {
    console.error("Scan lookup failed:", err);
    renderError("Could not retrieve scan results for this page.", hostname, tab.url);
  }

  wireButtons(tab);
}

/* ---------- Theme Switching ---------- */

function wireThemeToggle() {
  const toggleBtn = document.getElementById("themeToggleBtn");
  if (!toggleBtn) return;

  toggleBtn.addEventListener("click", () => {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const newTheme = currentTheme === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", newTheme);
    
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.sync) {
      localStorage.setItem("theme", newTheme);
      return;
    }
    
    chrome.storage?.sync?.set({ theme: newTheme }, () => {
      try {
        const p = chrome.runtime?.sendMessage?.({ type: "THEME_CHANGED", theme: newTheme });
        if (p && typeof p.catch === "function") p.catch(() => {});
      } catch {}
    });
  });
}

function applyStoredTheme() {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.sync) {
    let theme = "dark";
    try {
      if (typeof localStorage !== "undefined" && localStorage) {
        theme = localStorage.getItem("theme") === "light" ? "light" : "dark";
      }
    } catch {}
    if (document.documentElement && document.documentElement.setAttribute) {
      document.documentElement.setAttribute("data-theme", theme);
    }
    return;
  }
  chrome.storage?.sync?.get(["theme"], (result) => {
    const theme = result?.theme === "light" ? "light" : "dark";
    if (document.documentElement && document.documentElement.setAttribute) {
      document.documentElement.setAttribute("data-theme", theme);
    }
  });
}

if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "THEME_CHANGED" && message.theme) {
      document.documentElement.setAttribute("data-theme", message.theme);
    }
  });
}

/* ---------- Live Protection Switch ---------- */

function wireProtectionSwitch() {
  const pSwitch = document.getElementById("protectionSwitch");
  const pLabel = document.getElementById("protectionToggleStatus");
  if (!pSwitch || !pLabel) return;

  // Load saved state
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.sync) {
    const disabled = localStorage.getItem("protectionDisabled") === "true";
    pSwitch.checked = !disabled;
    updateSwitchUI(!disabled);
  } else {
    chrome.storage.sync.get(["protectionDisabled"], (result) => {
      const disabled = result?.protectionDisabled === true;
      pSwitch.checked = !disabled;
      updateSwitchUI(!disabled);
    });
  }

  pSwitch.addEventListener("change", (e) => {
    const active = e.target.checked;
    updateSwitchUI(active);
    
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.sync) {
      localStorage.setItem("protectionDisabled", !active);
    } else {
      chrome.storage.sync.set({ protectionDisabled: !active });
    }
  });
}

function updateSwitchUI(active) {
  const pLabel = document.getElementById("protectionToggleStatus");
  if (!pLabel) return;
  if (active) {
    pLabel.textContent = "ON";
    pLabel.className = "toggle-subtitle on";
  } else {
    pLabel.textContent = "OFF";
    pLabel.className = "toggle-subtitle off";
  }
}

/* ---------- Data + rendering ---------- */

// 240 degrees of circle cx="80" cy="65" r="54".
// Circumference = 2 * PI * 54 = 339.29.
// Gauge Active Arc Length = 240/360 * 339.29 = 226.2.
const GAUGE_CIRCUMFERENCE = 339.3;
const GAUGE_ARC_LIMIT = 226.2;

function setGaugeScore(score, colorVar) {
  const circle = document.getElementById("gaugeCircle");
  const scoreText = document.getElementById("securityScoreText");
  
  if (scoreText) {
    scoreText.textContent = score !== null ? score : "—";
  }
  
  if (circle) {
    if (score === null) {
      circle.style.strokeDashoffset = GAUGE_ARC_LIMIT;
      circle.style.stroke = "var(--border)";
      return;
    }
    // Map score 0-100 to offset 226.2 - 0
    const offset = GAUGE_ARC_LIMIT - (score / 100) * GAUGE_ARC_LIMIT;
    circle.style.strokeDashoffset = offset;
    circle.style.stroke = `var(${colorVar})`;
  }
}

/**
 * Swap the header logo (top-left) and hero logo (status panel) between the
 * 4 variants based on the current severity class:
 *   default  → icons/default_logo.jpeg  (no scan yet)
 *   allowed  → icons/green_logo.jpeg    (safe)
 *   caution  → icons/orange_logo.jpeg   (suspicious)
 *   blocked  → icons/red_logo.jpeg      (dangerous)
 *
 * Coloured logos (green/orange/red) are marked with the 'coloured' CSS class
 * so the light-mode inversion filter is NOT applied to them — they are already
 * the right colour and shouldn't be inverted.
 */
function updatePopupLogos(severityClass) {
  const LOGO_MAP = {
    default: "icons/default_logo.jpeg",
    allowed: "icons/green_logo.jpeg",
    caution: "icons/orange_logo.jpeg",
    blocked: "icons/red_logo.jpeg",
  };

  const src = LOGO_MAP[severityClass] || LOGO_MAP.default;
  const isColoured = severityClass !== "default";

  const headerImg = document.getElementById("headerLogoImg");
  const heroImg   = document.getElementById("heroLogoImg");

  [headerImg, heroImg].forEach((img) => {
    if (!img) return;
    img.src = src;
    // Add/remove 'coloured' class to control CSS filter inversion
    img.classList.toggle("coloured", isColoured);
  });
}

function showStatusBanner(type, text) {
  const banner = document.getElementById("statusBanner");
  const bannerText = document.getElementById("statusBannerText");
  if (!banner || !bannerText) return;
  banner.className = `status-banner ${type || ""}`.trim();
  bannerText.textContent = text;
  banner.style.display = "flex";
}

function hideStatusBanner() {
  const banner = document.getElementById("statusBanner");
  if (banner) banner.style.display = "none";
}

function renderResult(data, hostname, currentUrl) {
  if (!data) {
    renderError("No scan data available.", hostname, currentUrl);
    return;
  }

  const hShield = document.getElementById("heroShieldWrapper");
  const hTitle = document.getElementById("heroStatusTitle");
  const hBadge = document.getElementById("heroStatusBadge");
  const gRating = document.getElementById("securityScoreRating");

  const gridSSL = document.getElementById("gridSSLStatus");
  const gridRep = document.getElementById("gridReputationStatus");
  const gridThreat = document.getElementById("gridThreatsStatus");

  const toggleContainer = document.getElementById("protectionToggleContainer");
  const backBtn = document.getElementById("backBtn");

  const isHttps = currentUrl ? currentUrl.startsWith("https://") : true;
  const isHttp = currentUrl ? currentUrl.startsWith("http://") : false;
  const isInternal = currentUrl ? (currentUrl.startsWith("chrome://") || currentUrl.startsWith("chrome-extension://") || currentUrl.startsWith("about:") || currentUrl.startsWith("file://")) : false;

  // ── Scenario A: Backend Offline / Unverified / Local Heuristics ──────────
  if (data.isPlaceholder || typeof data.riskScore !== "number" || !Number.isFinite(data.riskScore)) {
    const errorMsg = data.reasons || "Model verdict unavailable. Ensure backend is reachable and connect the extension in Settings.";

    // Always pre-populate SSL Status cleanly from currentUrl
    if (gridSSL) {
            if (isHttp) {
        gridSSL.textContent = "Unencrypted (HTTP)";
        gridSSL.title = "Unencrypted plain HTTP connection (Insecure)";
        const item = getGridItem(gridSSL);
        if (item) item.className = "grid-item blocked";
      } else if (isInternal) {
        gridSSL.textContent = "Internal Page";
        gridSSL.title = "Local or browser internal page";
        const item = getGridItem(gridSSL);
        if (item) item.className = "grid-item";
      } else {
        gridSSL.textContent = "Encrypted (HTTPS)";
        gridSSL.title = "Verified HTTPS SSL/TLS encryption";
        const item = getGridItem(gridSSL);
        if (item) item.className = "grid-item allowed";
      }
    }

    // If local heuristic scan provided observations, display clean summary
    if (typeof data.heuristicScore === "number") {
      const indicators = Array.isArray(data.indicators) ? data.indicators : [];
      const heuristicSecScore = Math.max(0, Math.round(100 - data.heuristicScore));

      let heuristicSeverity = "allowed";
      let heroTitleText = "LOCAL SHIELD ACTIVE";
      let heroBadgeText = "LOCAL SCAN | LOW RISK";
      let ratingText = "GOOD (LOCAL)";
      let colorVar = "--success";
      let repText = "Local Check OK";
      let repTooltip = "No suspicious patterns detected by local heuristic inspection";

      if (data.heuristicScore >= 70) {
        heuristicSeverity = "blocked";
        heroTitleText = "SUSPICIOUS SITE";
        heroBadgeText = "LOCAL SHIELD | HIGH RISK";
        ratingText = "CRITICAL (LOCAL)";
        colorVar = "--danger";
        repText = "Suspicious Signs";
        repTooltip = indicators.join("; ") || "High risk characteristics flagged by local heuristics";
      } else if (data.heuristicScore >= 30) {
        heuristicSeverity = "caution";
        heroTitleText = "CAUTION SITE";
        heroBadgeText = "LOCAL SHIELD | CAUTION";
        ratingText = "CAUTION (LOCAL)";
        colorVar = "--warning";
        repText = "Caution Signs";
        repTooltip = indicators.join("; ") || "Suspicious patterns flagged by local heuristics";
      }

      // Hero
      if (hShield) hShield.className = `hero-shield-wrapper ${heuristicSeverity}`;
      updatePopupLogos(heuristicSeverity);
      if (hTitle) {
        hTitle.textContent = heroTitleText;
        hTitle.className = `hero-status-title ${heuristicSeverity}`;
      }
      if (hBadge) {
        hBadge.textContent = heroBadgeText;
        hBadge.className = `hero-status-badge ${heuristicSeverity}`;
      }

      // Gauge
      setGaugeScore(heuristicSecScore, colorVar);
      if (gRating) {
        gRating.textContent = ratingText;
        gRating.className = `gauge-sub-label ${heuristicSeverity}`;
      }

      // Reputation
      if (gridRep) {
        gridRep.textContent = repText;
        gridRep.title = repTooltip;
        const item = getGridItem(gridRep);
        if (item) item.className = `grid-item ${heuristicSeverity}`;
      }

      // Threats Box: Concise text (e.g. "Clean Scan", "Zero Threats", or "X Signals Flagged")
      if (gridThreat) {
        if (indicators.length > 0) {
          gridThreat.textContent = `${indicators.length} Signal${indicators.length > 1 ? "s" : ""} Flagged`;
          gridThreat.title = indicators.join("; ");
          const item = getGridItem(gridThreat);
          if (item) item.className = `grid-item ${heuristicSeverity}`;
        } else {
          gridThreat.textContent = "Clean Scan";
          gridThreat.title = "No suspicious characteristics found by local heuristic inspection.";
          const item = getGridItem(gridThreat);
          if (item) item.className = "grid-item allowed";
        }
      }

      // Banner explaining backend status
      showStatusBanner("info", "Cloud AI Offline • Local Shield Active");

      // Footer
      if (toggleContainer) toggleContainer.style.display = "flex";
      if (backBtn) backBtn.style.display = "none";
    } else {
      // Complete fallback when no heuristics available
      renderError(errorMsg, hostname, currentUrl);
      showStatusBanner("warning", "Cloud AI Offline • Connect Dashboard");
    }
    return;
  }

  // ── Scenario B: Authoritative Cloud AI / LightGBM Verified Verdict ────────
  hideStatusBanner();

  const { riskScore = 0, status = "Unknown", reasons, indicators = [] } = data;
  const securityScore = Math.max(0, Math.round(100 - riskScore));

  let severityClass = "allowed";
  let displayTitle = "SAFE SITE";
  let displayBadge = "AI VERIFIED | LOW RISK";
  let displayRating = "EXCELLENT";
  let colorVar = "--success";
  let repText = "Highly Trusted";
  let threatsText = "Clean Scan";

  if (riskScore >= 70) {
    severityClass = "blocked";
    displayTitle = "DANGEROUS SITE";
    displayBadge = "AI VERIFIED | HIGH RISK";
    displayRating = "CRITICAL";
    colorVar = "--danger";
    repText = "Untrusted Domain";
    threatsText = `${indicators.length || 1} Threat(s) Found`;
  } else if (riskScore >= 30) {
    severityClass = "caution";
    displayTitle = "SUSPICIOUS SITE";
    displayBadge = "AI VERIFIED | MEDIUM RISK";
    displayRating = "CAUTION";
    colorVar = "--warning";
    repText = "Low Trust Domain";
    threatsText = `${indicators.length || 1} Suspicious Signal(s)`;
  }

  // Hero Status Area + Logos
  if (hShield) hShield.className = `hero-shield-wrapper ${severityClass}`;
  updatePopupLogos(severityClass);
  if (hTitle) {
    hTitle.textContent = displayTitle;
    hTitle.className = `hero-status-title ${severityClass}`;
  }
  if (hBadge) {
    hBadge.textContent = displayBadge;
    hBadge.className = `hero-status-badge ${severityClass}`;
  }

  // Gauge Progress
  setGaugeScore(securityScore, colorVar);
  if (gRating) {
    gRating.textContent = displayRating;
    gRating.className = `gauge-sub-label ${severityClass}`;
  }

  // 2x2 Details Grid
  const httpCheck = indicators.some((ind) => ind.includes("HTTP") || ind.includes("not encrypted"));
  if (gridSSL) {
    if (httpCheck || isHttp) {
      gridSSL.textContent = "Unencrypted (HTTP)";
      gridSSL.title = "Unencrypted plain HTTP connection (Insecure)";
      const item = getGridItem(gridSSL);
      if (item) item.className = "grid-item blocked";
    } else if (isInternal) {
      gridSSL.textContent = "Internal Page";
      gridSSL.title = "Local or browser internal page";
      const item = getGridItem(gridSSL);
      if (item) item.className = "grid-item";
    } else {
      gridSSL.textContent = "Encrypted (HTTPS)";
      gridSSL.title = "Verified HTTPS SSL/TLS encryption";
      const item = getGridItem(gridSSL);
      if (item) item.className = "grid-item allowed";
    }
  }

  if (gridRep) {
    gridRep.textContent = repText;
    gridRep.title = `Domain reputation verified by SCYTHE multi-tier pipeline: ${repText}`;
    const item = getGridItem(gridRep);
    if (item) item.className = `grid-item ${severityClass}`;
  }

  if (gridThreat) {
    gridThreat.textContent = threatsText;
    gridThreat.title = reasons || (indicators.length > 0 ? indicators.join("; ") : "Zero malicious signals detected across all inspection tiers");
    const item = getGridItem(gridThreat);
    if (item) item.className = `grid-item ${severityClass}`;
  }

  // Footer Actions
  if (riskScore >= 70) {
    if (toggleContainer) toggleContainer.style.display = "none";
    if (backBtn) backBtn.style.display = "inline-flex";
  } else {
    if (toggleContainer) toggleContainer.style.display = "flex";
    if (backBtn) backBtn.style.display = "none";
  }
}

function renderError(message, hostname, currentUrl) {
  setGaugeScore(null, "--border");

  const hShield = document.getElementById("heroShieldWrapper");
  const hTitle = document.getElementById("heroStatusTitle");
  const hBadge = document.getElementById("heroStatusBadge");
  const gRating = document.getElementById("securityScoreRating");

  if (hShield) hShield.className = "hero-shield-wrapper";
  updatePopupLogos("default");
  if (hTitle) {
    hTitle.textContent = "VERDICT UNAVAILABLE";
    hTitle.className = "hero-status-title";
  }
  if (hBadge) {
    hBadge.textContent = "UNKNOWN";
    hBadge.className = "hero-status-badge";
  }
  if (gRating) {
    gRating.textContent = "OFFLINE";
    gRating.className = "gauge-sub-label";
  }

  const gridSSL = document.getElementById("gridSSLStatus");
  const gridRep = document.getElementById("gridReputationStatus");
  const gridThreat = document.getElementById("gridThreatsStatus");

  const isHttps = currentUrl ? currentUrl.startsWith("https://") : true;
  const isHttp = currentUrl ? currentUrl.startsWith("http://") : false;
  const isInternal = currentUrl ? (currentUrl.startsWith("chrome://") || currentUrl.startsWith("chrome-extension://") || currentUrl.startsWith("about:") || currentUrl.startsWith("file://")) : false;

  if (gridSSL) {
    if (isHttp) {
      gridSSL.textContent = "Unencrypted (HTTP)";
      gridSSL.title = "Unencrypted plain HTTP connection (Insecure)";
      const item = getGridItem(gridSSL);
      if (item) item.className = "grid-item blocked";
    } else if (isInternal) {
      gridSSL.textContent = "Internal Page";
      gridSSL.title = "Local or browser internal page";
      const item = getGridItem(gridSSL);
      if (item) item.className = "grid-item";
    } else {
      gridSSL.textContent = "Encrypted (HTTPS)";
      gridSSL.title = "Verified HTTPS SSL/TLS encryption";
      const item = getGridItem(gridSSL);
      if (item) item.className = "grid-item allowed";
    }
  }

  if (gridRep) {
    gridRep.textContent = "—";
    gridRep.title = "Reputation data unavailable offline";
    const item = getGridItem(gridRep);
    if (item) item.className = "grid-item";
  }

  if (gridThreat) {
    gridThreat.textContent = "Verdict Unavailable";
    gridThreat.title = message || "Cannot reach SCYTHE analysis engine";
    const item = getGridItem(gridThreat);
    if (item) item.className = "grid-item";
  }

  showStatusBanner("warning", "Cloud AI Offline • Connect Dashboard");

  const toggleContainer = document.getElementById("protectionToggleContainer");
  const backBtn = document.getElementById("backBtn");
  if (toggleContainer) toggleContainer.style.display = "flex";
  if (backBtn) backBtn.style.display = "none";
}

/* ---------- Buttons ---------- */

function wireButtons(tab) {
  const backBtn = document.getElementById("backBtn");
  const dashboardBtn = document.getElementById("dashboardBtn");
  const deepScanBtn = document.getElementById("deepScanBtn");
  if (deepScanBtn) deepScanBtn.addEventListener("click", async () => {
    deepScanBtn.disabled = true;
    try {
      const result = await sendMessage({ type: "TRIGGER_STAGE2", tabId: tab?.id, url: tab?.url });
      if (!result?.ok || !result.scanId) throw new Error(result?.error || "Deep scan unavailable.");
      const report = new URL("report.html", DASHBOARD_URL);
      report.searchParams.set("scan_id", result.scanId);
      chrome.tabs.create({ url: report.href });
    } catch (error) { renderError(error.message, safeHostname(tab?.url || "")); }
    finally { deepScanBtn.disabled = false; }
  });

  if (backBtn) {
    backBtn.onclick = () => {
      if (typeof chrome !== "undefined" && chrome.tabs) {
        if (tab?.id) {
          chrome.tabs.goBack ? chrome.tabs.goBack(tab.id) : chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => window.history.back(),
          });
        }
      } else {
        console.log("Mock Go Back clicked.");
      }
      window.close();
    };
  }

  if (dashboardBtn) {
    dashboardBtn.onclick = () => {
      if (typeof chrome !== "undefined" && chrome.tabs) {
        chrome.tabs.create({ url: DASHBOARD_URL });
      } else {
        window.open(DASHBOARD_URL, "_blank");
      }
    };
  }
}

/* ---------- Helpers ---------- */

function getActiveTab() {
  return new Promise((resolve) => {
    if (typeof chrome === "undefined" || !chrome.tabs) {
      resolve(null);
      return;
    }
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs && tabs[0] ? tabs[0] : null);
    });
  });
}

function sendMessage(payload) {
  return new Promise((resolve, reject) => {
    if (typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.sendMessage) {
      reject(new Error("Browser extension messaging is unavailable."));
      return;
    }
    chrome.runtime.sendMessage(payload, (response) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
        return;
      }
      resolve(response);
    });
  });
}

function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "Unknown";
  }
}
