// popup.js
// Logic for the extension's popup.html — pulls scan data for the active tab,
// renders it into the UI, and wires up the action buttons, theme toggle, and live protection.

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

  // Display URL in top hero card
  const hostname = safeHostname(tab.url);
  document.getElementById("heroUrl").textContent = hostname;
  document.getElementById("gridSiteUrl").textContent = hostname;

  try {
    // Ask the background/service worker for the scan result of this tab.
    const result = await sendMessage({ type: "GET_SCAN_RESULT", tabId: tab.id, url: tab.url });
    renderResult(result, hostname);
  } catch (err) {
    console.error("Scan lookup failed:", err);
    renderError("Could not retrieve scan results for this page.", hostname);
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
      chrome.runtime.sendMessage({ type: "THEME_CHANGED", theme: newTheme }).catch(() => {});
    });
  });
}

function applyStoredTheme() {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.sync) {
    const theme = localStorage.getItem("theme") === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", theme);
    return;
  }
  chrome.storage?.sync?.get(["theme"], (result) => {
    const theme = result?.theme === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", theme);
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

function renderResult(data, hostname) {
  if (!data) {
    renderError("No scan data available.", hostname);
    return;
  }

  const { riskScore = 0, status = "Unknown", reasons, indicators = [] } = data;
  const securityScore = Math.max(0, 100 - riskScore);

  // References to DOM elements
  const hShield = document.getElementById("heroShieldWrapper");
  const hTitle = document.getElementById("heroStatusTitle");
  const hBadge = document.getElementById("heroStatusBadge");
  const gRating = document.getElementById("securityScoreRating");

  const gridSSL = document.getElementById("gridSSLStatus");
  const gridSSLIcon = document.getElementById("gridSSLIcon");
  const gridRep = document.getElementById("gridReputationStatus");
  const gridRepIcon = document.getElementById("gridReputationIcon");
  const gridThreat = document.getElementById("gridThreatsStatus");
  const gridThreatIcon = document.getElementById("gridThreatsIcon");

  const toggleContainer = document.getElementById("protectionToggleContainer");
  const backBtn = document.getElementById("backBtn");

  // Determine severity tier based on riskScore
  let severityClass = "allowed";
  let displayTitle = "SAFE SITE";
  let displayBadge = "SECURE | LOW RISK";
  let displayRating = "EXCELLENT";
  let colorVar = "--success";

  if (riskScore >= 70) {
    severityClass = "blocked";
    displayTitle = "DANGEROUS SITE";
    displayBadge = "UNSAFE | HIGH RISK";
    displayRating = "CRITICAL";
    colorVar = "--danger";
  } else if (riskScore >= 30) {
    severityClass = "caution";
    displayTitle = "SUSPICIOUS SITE";
    displayBadge = "WARNING | MEDIUM RISK";
    displayRating = "CAUTION";
    colorVar = "--warning";
  }

  // 1. Update Hero Status Area
  if (hShield) hShield.className = `hero-shield-wrapper ${severityClass}`;
  if (hTitle) {
    hTitle.textContent = displayTitle;
    hTitle.className = `hero-status-title ${severityClass}`;
  }
  if (hBadge) {
    hBadge.textContent = displayBadge;
    hBadge.className = `hero-status-badge ${severityClass}`;
  }

  // 2. Set Gauge Arc Progress
  setGaugeScore(securityScore, colorVar);
  if (gRating) {
    gRating.textContent = displayRating;
    gRating.className = `gauge-sub-label ${severityClass}`;
  }

  // 3. Populate 2x2 Details Grid
  // SSL Check (Local HTTP check)
  const isHttps = window.location ? !hostname.startsWith("localhost") && !hostname.startsWith("127.0.0.1") : true; // Local extension checks
  const httpCheck = indicators.some(ind => ind.includes("HTTP") || ind.includes("not encrypted"));
  
  if (gridSSL) {
    if (httpCheck) {
      gridSSL.textContent = "Unencrypted (HTTP)";
      gridSSL.parentNode.parentNode.className = "grid-item blocked";
    } else {
      gridSSL.textContent = "Encrypted (HTTPS)";
      gridSSL.parentNode.parentNode.className = "grid-item allowed";
    }
  }

  // Reputation Check
  if (gridRep) {
    if (riskScore >= 70) {
      gridRep.textContent = "Untrusted Domain";
      gridRep.parentNode.parentNode.className = "grid-item blocked";
    } else if (riskScore >= 30) {
      gridRep.textContent = "Low Trust Domain";
      gridRep.parentNode.parentNode.className = "grid-item caution";
    } else {
      gridRep.textContent = "Highly Trusted";
      gridRep.parentNode.parentNode.className = "grid-item allowed";
    }
  }

  // Threats found Check
  if (gridThreat) {
    if (indicators.length > 0) {
      gridThreat.textContent = `${indicators.length} Threat${indicators.length > 1 ? 's' : ''} Found`;
      gridThreat.parentNode.parentNode.className = `grid-item ${severityClass}`;
    } else {
      gridThreat.textContent = "Clean Scan";
      gridThreat.parentNode.parentNode.className = "grid-item allowed";
    }
  }

  // 4. Update Footer state (Toggle vs Go Back)
  if (riskScore >= 70) {
    if (toggleContainer) toggleContainer.style.display = "none";
    if (backBtn) backBtn.style.display = "inline-flex";
  } else {
    if (toggleContainer) toggleContainer.style.display = "flex";
    if (backBtn) backBtn.style.display = "none";
  }
}

function renderError(message, hostname) {
  setGaugeScore(null, "--border");
  
  const hShield = document.getElementById("heroShieldWrapper");
  const hTitle = document.getElementById("heroStatusTitle");
  const hBadge = document.getElementById("heroStatusBadge");
  const gRating = document.getElementById("securityScoreRating");

  if (hShield) hShield.className = "hero-shield-wrapper";
  if (hTitle) {
    hTitle.textContent = "SCAN OFFLINE";
    hTitle.className = "hero-status-title";
  }
  if (hBadge) {
    hBadge.textContent = "UNABLE TO VERIFY";
    hBadge.className = "hero-status-badge";
  }
  if (gRating) {
    gRating.textContent = "ERROR";
    gRating.className = "gauge-sub-label";
  }

  const gridSSL = document.getElementById("gridSSLStatus");
  const gridRep = document.getElementById("gridReputationStatus");
  const gridThreat = document.getElementById("gridThreatsStatus");

  if (gridSSL) gridSSL.textContent = "—";
  if (gridRep) gridRep.textContent = "—";
  if (gridThreat) gridThreat.textContent = message || "Connection Failed";

  // Re-enable toggle but hide back button
  const toggleContainer = document.getElementById("protectionToggleContainer");
  const backBtn = document.getElementById("backBtn");
  if (toggleContainer) toggleContainer.style.display = "flex";
  if (backBtn) backBtn.style.display = "none";
}

/* ---------- Buttons ---------- */

function wireButtons(tab) {
  const backBtn = document.getElementById("backBtn");
  const dashboardBtn = document.getElementById("dashboardBtn");

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
        chrome.tabs.create({ url: "http://localhost:3000/dashboard" });
      } else {
        window.open("http://localhost:3000/dashboard", "_blank");
      }
    };
  }
}

/* ---------- Helpers ---------- */

function getActiveTab() {
  return new Promise((resolve) => {
    if (typeof chrome === "undefined" || !chrome.tabs) {
      // Default mock url for browser testing
      resolve({ id: 1, url: "https://secure-login-warning-caution.phishing.com/login" });
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
      const url = payload.url || "";
      if (url.includes("phishing") || url.includes("blocked")) {
        resolve({
          riskScore: 82,
          status: "Blocked",
          reasons: "AEGIS detected known deceptive credential forms and spoofed brand imagery on this page.",
          indicators: ["Deceptive login form detected", "Domain matches phishing blocklist", "Connection uses HTTP"],
          scannedAt: Date.now()
        });
      } else if (url.includes("caution") || url.includes("warning")) {
        resolve({
          riskScore: 45,
          status: "Caution",
          reasons: "Local heuristics flagged suspicious spelling matching high-profile domains.",
          indicators: ["Suspicious domain keyword spoofing", "Multiple hyphens in URL"],
          scannedAt: Date.now()
        });
      } else {
        resolve({
          riskScore: 8,
          status: "Allowed",
          reasons: "No threat indicators detected. The domain signature is clean and verified.",
          indicators: [],
          scannedAt: Date.now()
        });
      }
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