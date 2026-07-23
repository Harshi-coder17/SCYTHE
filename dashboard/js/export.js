/* ============================================================
   Export Engine — builds a formatted PDF or JPG report.
   Uses jsPDF + html2canvas loaded via CDN from report.html.
   ============================================================ */

/* ---------- Helpers ---------- */
const EX_COLORS = {
  dark: { bg: "#0a101c", panel: "#111b31", border: "#25375c", text: "#f6f8ff", muted: "#93a1c7", accent: "#7263ff", ok: "#2fe6a0", warn: "#ffb92e", danger: "#ff5568" },
  light: { bg: "#f6f8fc", panel: "#ffffff", border: "#d8e2ef", text: "#1f2937", muted: "#64748b", accent: "#5b4bdb", ok: "#16a34a", warn: "#f59e0b", danger: "#ef4444" },
};

function getExTheme() {
  const toggle = document.getElementById("export-theme-toggle");
  if (toggle) {
    return toggle.checked ? EX_COLORS.dark : EX_COLORS.light;
  }
  return document.documentElement.getAttribute("data-theme") === "light" ? EX_COLORS.light : EX_COLORS.dark;
}

/* Page dimension map (points: 1pt = 1/72 in) */
const PAGE_SIZES = {
  a4: [595.28, 841.89],
  letter: [612, 792],
  a3: [841.89, 1190.55],
  fit: null, // determined at render time
};

/* ---------- Modal open / close ---------- */
function openExportModal() {
  document.getElementById("export-overlay").classList.add("open");
  document.body.style.overflow = "hidden";
  // Always render preview when modal opens
  setTimeout(updateExportPreview, 50);
}

function closeExportModal() {
  document.getElementById("export-overlay").classList.remove("open");
  document.body.style.overflow = "";
}

/* Close on overlay click (not modal itself) */
document.addEventListener("click", (e) => {
  const overlay = document.getElementById("export-overlay");
  if (e.target === overlay) closeExportModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeExportModal();
});

/* ---------- Format toggle ---------- */
function setExportFormat(format) {
  document.querySelectorAll('.export-format-toggle label').forEach((l) => l.classList.remove('active'));
  const active = document.querySelector(`.export-format-toggle label[data-format="${format}"]`);
  if (active) active.classList.add('active');

  // Show/hide size selector (JPG doesn't use page sizes)
  const sizeGroup = document.getElementById("export-size-group");
  if (sizeGroup) sizeGroup.style.display = format === "jpg" ? "none" : "";
}

/* ---------- Core: Build the off-screen report DOM ---------- */
function buildReportDom(report, sections) {
  const C = getExTheme();
  const wrap = document.createElement("div");
  wrap.style.cssText = `
    width:760px; font-family:'Inter','Segoe UI',sans-serif; background:${C.bg}; color:${C.text};
    padding:0; margin:0; line-height:1.55;
  `;

  /* Utility: section container */
  const sec = (title) => {
    const s = document.createElement("div");
    s.style.cssText = `padding:32px 40px 28px; border-bottom:1px solid ${C.border};`;
    if (title) {
      const h = document.createElement("div");
      h.style.cssText = `font-family:'Chakra Petch','Inter',sans-serif; font-size:13px; font-weight:700; letter-spacing:0.18em; text-transform:uppercase; color:${C.accent}; margin-bottom:16px;`;
      h.textContent = title;
      s.appendChild(h);
    }
    return s;
  };

  /* Utility: key-value row */
  const kvRow = (key, value, flagged) => {
    const r = document.createElement("div");
    r.style.cssText = `display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid ${C.border}22;`;
    const k = document.createElement("span");
    k.style.cssText = `font-size:13px; color:${C.muted};`;
    k.textContent = key;
    const v = document.createElement("span");
    if (flagged === true) {
      v.style.cssText = `font-size:12px; font-weight:600; padding:3px 10px; border-radius:6px; background:${C.danger}20; color:${C.danger};`;
    } else if (flagged === false) {
      v.style.cssText = `font-size:12px; font-weight:600; padding:3px 10px; border-radius:6px; background:${C.ok}20; color:${C.ok};`;
    } else {
      v.style.cssText = `font-size:13px; color:${C.text};`;
    }
    v.textContent = String(value);
    r.appendChild(k);
    r.appendChild(v);
    return r;
  };

  /* ======= COVER / BASIC DETAILS (always included) ======= */
  if (sections.basics) {
    const cover = sec(null);
    // Brand header
    const brand = document.createElement("div");
    brand.style.cssText = `display:flex; align-items:center; gap:14px; margin-bottom:28px;`;
    const logoBox = document.createElement("div");
    logoBox.style.cssText = `width:40px; height:40px; background:${C.accent}; border-radius:10px; display:flex; align-items:center; justify-content:center;`;
    logoBox.innerHTML = `<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#fff" stroke-width="2"><path d="M12 2 L20 6 v6 c0 5-4 8-8 10 C8 20 4 17 4 12 V6 Z"/></svg>`;
    const brandText = document.createElement("div");
    brandText.innerHTML = `<div style="font-family:'Chakra Petch','Inter',sans-serif;font-size:20px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;">CyberWeb</div><div style="font-size:11px;color:${C.muted};letter-spacing:0.1em;">THREAT ANALYSIS REPORT</div>`;
    brand.appendChild(logoBox);
    brand.appendChild(brandText);

    // Timestamp right-aligned
    const tsBox = document.createElement("div");
    tsBox.style.cssText = `margin-left:auto; text-align:right; font-size:11px; color:${C.muted}; line-height:1.6;`;
    tsBox.innerHTML = `Generated: ${new Date().toLocaleString()}<br>Report ID: ${report.id}`;
    brand.appendChild(tsBox);
    cover.appendChild(brand);

    // Verdict banner
    const verdictColor = report.verdict === "SAFE" ? C.ok : report.verdict === "SUSPICIOUS" ? C.warn : C.danger;
    const vBanner = document.createElement("div");
    vBanner.style.cssText = `background:${verdictColor}18; border:1px solid ${verdictColor}44; border-radius:12px; padding:18px 24px; display:flex; align-items:center; justify-content:space-between; margin-bottom:24px;`;
    vBanner.innerHTML = `
      <div>
        <div style="font-size:11px;color:${C.muted};letter-spacing:0.14em;text-transform:uppercase;margin-bottom:4px;">Overall Verdict</div>
        <div style="font-size:22px;font-weight:800;color:${verdictColor};font-family:'Chakra Petch','Inter',sans-serif;">${report.verdict}</div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:11px;color:${C.muted};letter-spacing:0.14em;text-transform:uppercase;margin-bottom:4px;">Risk Score</div>
        <div style="font-size:28px;font-weight:800;color:${verdictColor};font-family:'Chakra Petch','Inter',sans-serif;">${report.riskScore}<span style="font-size:14px;color:${C.muted}">/100</span></div>
      </div>
    `;
    cover.appendChild(vBanner);

    // Basic details grid
    const grid = document.createElement("div");
    grid.style.cssText = `display:grid; grid-template-columns:1fr 1fr; gap:12px;`;
    const basicFields = [
      ["Scanned URL", report.url],
      ["Host", report.host],
      ["Scanned At", report.scannedAt],
      ["Threats Found", report.detected.length],
    ];
    basicFields.forEach(([k, v]) => {
      const cell = document.createElement("div");
      cell.style.cssText = `background:${C.panel}; border:1px solid ${C.border}; border-radius:10px; padding:14px 16px;`;
      cell.innerHTML = `<div style="font-size:10px;color:${C.muted};letter-spacing:0.14em;text-transform:uppercase;margin-bottom:5px;">${k}</div><div style="font-size:13px;color:${C.text};word-break:break-all;">${v}</div>`;
      grid.appendChild(cell);
    });
    cover.appendChild(grid);
    wrap.appendChild(cover);
  }

  /* ======= SCAN RESULTS ======= */
  if (sections.scan) {
    const s = sec("Scan Results");

    // Score bars
    const scoreBar = (label, value, max, color) => {
      const row = document.createElement("div");
      row.style.cssText = `margin-bottom:14px;`;
      row.innerHTML = `
        <div style="display:flex;justify-content:space-between;margin-bottom:5px;">
          <span style="font-size:12px;color:${C.muted};">${label}</span>
          <span style="font-size:13px;font-weight:700;color:${color};">${typeof value === "number" && max === 100 ? value + "%" : value}</span>
        </div>
        <div style="height:8px;background:${C.border};border-radius:4px;overflow:hidden;">
          <div style="height:100%;width:${(value / max) * 100}%;background:${color};border-radius:4px;"></div>
        </div>
      `;
      return row;
    };
    const legitColor = report.legitimacy >= 70 ? C.ok : report.legitimacy >= 45 ? C.warn : C.danger;
    s.appendChild(scoreBar("Legitimacy Score", report.legitimacy, 100, legitColor));
    s.appendChild(scoreBar("AI Model Confidence", report.aiConfidence.toFixed(1) + "%", 100, C.accent));

    // Threats
    if (report.detected.length) {
      const tHead = document.createElement("div");
      tHead.style.cssText = `font-size:12px;font-weight:600;color:${C.text};margin:18px 0 10px;`;
      tHead.textContent = `Detected Threats (${report.detected.length})`;
      s.appendChild(tHead);
      report.detected.forEach((t) => {
        const tr = document.createElement("div");
        tr.style.cssText = `display:flex;align-items:center;gap:8px;padding:8px 12px;background:${C.danger}12;border-radius:8px;margin-bottom:6px;`;
        tr.innerHTML = `<span style="width:8px;height:8px;border-radius:50%;background:${C.danger};flex-shrink:0;"></span><span style="font-size:13px;color:${C.text};">${t}</span>`;
        s.appendChild(tr);
      });
    } else {
      const noT = document.createElement("div");
      noT.style.cssText = `padding:10px 14px;background:${C.ok}14;border-radius:8px;font-size:13px;color:${C.ok};margin-top:14px;`;
      noT.textContent = "✓ No threats detected";
      s.appendChild(noT);
    }
    wrap.appendChild(s);
  }

  /* ======= CYBER INTEL ======= */
  if (sections.intel) {
    const s = sec("Cyber Intelligence");
    const i = report.intel;

    const sub = (title) => {
      const h = document.createElement("div");
      h.style.cssText = `font-size:12px;font-weight:700;color:${C.text};margin:14px 0 8px;`;
      h.textContent = title;
      return h;
    };
    s.appendChild(sub("Domain Intel"));
    [["Registrar", i.domain], ["Domain Age", i.age], ["Confidence", i.confidence], ["IP Address", i.ip], ["Threat Count", i.threat], ["Expiration", i.expiration]].forEach(([k, v]) => s.appendChild(kvRow(k, v)));

    s.appendChild(sub("Reputation"));
    const safe = ["Safe", "No", "Not Detected"];
    const danger = ["Unsafe", "Yes", "Detected"];
    [["Brand Similarity", i.brandSimilarity], ["Fake Characters", i.fakeCharacters], ["URL Shortener", i.urlShortener], ["Host Reputation", i.reputation]].forEach(([k, v]) => {
      const flagged = safe.includes(v) ? false : danger.includes(v) ? true : undefined;
      s.appendChild(kvRow(k, v, flagged));
    });
    wrap.appendChild(s);
  }

  /* ======= SANDBOX SCREENSHOTS ======= */
  if (sections.screenshots) {
    const s = sec("Sandbox — Screenshot Capture");
    const sg = document.createElement("div");
    sg.style.cssText = `display:grid; grid-template-columns:1fr 1fr; gap:14px;`;

    const addThumb = (label, src) => {
      const card = document.createElement("div");
      card.style.cssText = `border:1px solid ${C.border}; border-radius:10px; overflow:hidden; background:${C.panel};`;
      const img = document.createElement("img");
      img.src = src;
      img.alt = label;
      img.style.cssText = `width:100%; height:auto; display:block;`;
      card.appendChild(img);
      const cap = document.createElement("div");
      cap.style.cssText = `padding:8px 12px; font-size:10px; letter-spacing:0.1em; text-transform:uppercase; color:${C.muted}; border-top:1px solid ${C.border};`;
      cap.textContent = label;
      card.appendChild(cap);
      sg.appendChild(card);
    };

    addThumb("Homepage Capture", report.sandbox.screenshots.homepage);
    addThumb("Full Page Capture", report.sandbox.screenshots.fullpage);
    s.appendChild(sg);
    wrap.appendChild(s);
  }

  /* ======= AI INSIGHTS ======= */
  if (sections.aiInsights && report.aiInsights) {
    const s = sec("AI Insights");
    const ai = report.aiInsights;

    s.appendChild(kvRow("Analysis Status", ai.core?.status || "Completed"));
    s.appendChild(kvRow("Global Risk Score", (ai.core?.globalRisk || 0) + "/100", (ai.core?.globalRisk || 0) >= 75));
    s.appendChild(kvRow("Visual Clone Verdict", ai.visual?.verdict || "—", ai.visual?.isClone));
    s.appendChild(kvRow("Model Confidence", (ai.visual?.confidence || 0) + "%"));

    if (ai.brand && ai.brand.target !== "None Detected") {
      s.appendChild(kvRow("Impersonation Target", ai.brand.target, true));
      s.appendChild(kvRow("Impersonation Confidence", (ai.brand.confidence || 0) + "%"));
    }

    if (ai.policy && ai.policy.length) {
      ai.policy.forEach((p) => {
        s.appendChild(kvRow("Policy Violation: " + p.name, p.value + " (Limit: " + p.limit + ")", true));
      });
    }

    wrap.appendChild(s);
  }

  /* ======= SANDBOX SECURITY & REDIRECTS ======= */
  if (sections.security) {
    const s = sec("Sandbox — Security & Redirects");
    const sb = report.sandbox;
    s.appendChild(kvRow("Security Headers", sb.securityHeadersPresent));
    s.appendChild(kvRow("Brand Impersonation", sb.brandImpersonationMatch ? `${sb.brandImpersonationMatch.brand} (${Math.round(sb.brandImpersonationMatch.similarity * 100)}%)` : "Not detected", !!sb.brandImpersonationMatch));
    s.appendChild(kvRow("QR Code Detected", sb.qrCodeDetected ? "Detected" : "Not detected", sb.qrCodeDetected));
    s.appendChild(kvRow("Cloaking Detected", sb.cloakingDetected ? "Detected" : "Not detected", sb.cloakingDetected));
    if (sb.redirects.length) {
      sb.redirects.forEach((r) => s.appendChild(kvRow(`Redirect (${r.httpStatusCode})`, r.redirectUrl)));
    } else {
      s.appendChild(kvRow("Redirects", "None"));
    }
    wrap.appendChild(s);
  }

  /* ======= SANDBOX STATS & BEHAVIOUR ======= */
  if (sections.behaviour) {
    const s = sec("Sandbox — Stats & Behaviour Summary");
    const sb = report.sandbox;

    // Stats grid
    const statsGrid = document.createElement("div");
    statsGrid.style.cssText = `display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:20px;`;
    [["Total Requests", sb.totalRequestCount], ["3rd-Party Domains", sb.thirdPartyDomainCount], ["Popups", sb.popupCount], ["Downloads", sb.downloads.length]].forEach(([k, v]) => {
      const cell = document.createElement("div");
      cell.style.cssText = `text-align:center; background:${C.panel}; border:1px solid ${C.border}; border-radius:10px; padding:14px 8px;`;
      cell.innerHTML = `<div style="font-size:10px;color:${C.muted};letter-spacing:0.12em;text-transform:uppercase;margin-bottom:4px;">${k}</div><div style="font-size:20px;font-weight:700;color:${C.text};font-family:'Chakra Petch','Inter',sans-serif;">${v}</div>`;
      statsGrid.appendChild(cell);
    });
    s.appendChild(statsGrid);

    // Behaviour rows
    const bRow = (label, value, flag) => s.appendChild(kvRow(label, value, flag ? true : undefined));
    bRow("XHR Requests", sb.xhrRequestCount, sb.xhrRequestCount >= 15);
    bRow("WebSocket Connections", sb.websocketConnectionCount, sb.websocketConnectionCount >= 1);
    bRow("Fingerprinting API Calls", sb.fingerprintingApiCount, sb.fingerprintingApiCount >= 1);
    bRow("New Tabs Opened", sb.newTabCount, sb.newTabCount >= 1);
    bRow("Clipboard Read Attempts", sb.clipboardReadAttempts, sb.clipboardReadAttempts >= 1);
    bRow("Clipboard Write Attempts", sb.clipboardWriteAttempts, sb.clipboardWriteAttempts >= 1);
    bRow("Permission Requests", sb.permissionRequests.length ? sb.permissionRequests.join(", ") : "None", sb.permissionRequests.length >= 1);
    bRow("Password Fields", sb.passwordFieldCount, sb.passwordFieldCount >= 1);
    bRow("Email Fields", sb.emailFieldCount, sb.emailFieldCount >= 1);
    bRow("Cross-Domain Forms", sb.crossDomainFormCount, sb.crossDomainFormCount >= 1);
    bRow("Hidden iFrames", sb.hiddenIframeCount, sb.hiddenIframeCount >= 1);
    bRow("External Scripts", sb.externalScriptCount, sb.externalScriptCount >= 6);
    bRow("Base64-Encoded Scripts", sb.base64EncodedScriptCount, sb.base64EncodedScriptCount >= 1);

    // Evasion
    if (sb.evasionTechniques.length) {
      sb.evasionTechniques.forEach((t) => s.appendChild(kvRow(t.name, t.flagged ? "Flagged" : "Clear", t.flagged)));
    }
    // Downloads
    if (sb.downloads.length) {
      sb.downloads.forEach((d) => s.appendChild(kvRow(d.fileName, (d.fileSizeBytes / 1024).toFixed(1) + " KB", true)));
    }
    // Sandbox verdict
    s.appendChild(kvRow("Sandbox Verdict", sb.verdict, sb.verdict !== "SAFE"));

    wrap.appendChild(s);
  }

  /* Footer */
  const footer = document.createElement("div");
  footer.style.cssText = `padding:20px 40px; text-align:center; font-size:10px; color:${C.muted}; letter-spacing:0.08em;`;
  footer.textContent = `CyberWeb Threat Analysis Report • Generated ${new Date().toLocaleString()} • Confidential`;
  wrap.appendChild(footer);

  return wrap;
}

/* ---------- Get selected sections from checkboxes ---------- */
function getSelectedSections() {
  return {
    basics: document.getElementById("ex-basics").checked,
    scan: document.getElementById("ex-scan").checked,
    intel: document.getElementById("ex-intel").checked,
    screenshots: document.getElementById("ex-screenshots").checked,
    aiInsights: document.getElementById("ex-aiinsights") ? document.getElementById("ex-aiinsights").checked : false,
    security: document.getElementById("ex-security").checked,
    behaviour: document.getElementById("ex-behaviour").checked,
  };
}

function getSelectedFormat() {
  const active = document.querySelector('.export-format-toggle label.active');
  return active ? active.getAttribute('data-format') : 'pdf';
}

function getSelectedSize() {
  return document.getElementById("export-size").value;
}

/* ---------- Generate PDF ---------- */
async function generatePdfReport() {
  const btn = document.getElementById("export-download-btn");
  btn.classList.add("loading");

  try {
    const sections = getSelectedSections();
    const sizeKey = getSelectedSize();
    const dom = buildReportDom(report, sections);

    // Temporarily attach off-screen for html2canvas
    dom.style.position = "fixed";
    dom.style.left = "-9999px";
    dom.style.top = "0";
    document.body.appendChild(dom);

    // Wait a tick for images to render
    await new Promise((r) => setTimeout(r, 200));

    const canvas = await html2canvas(dom, {
      scale: 2,
      useCORS: true,
      backgroundColor: getExTheme().bg,
      logging: false,
    });

    document.body.removeChild(dom);

    const imgData = canvas.toDataURL("image/png");
    const imgW = canvas.width;
    const imgH = canvas.height;

    // PDF creation
    const { jsPDF } = window.jspdf;

    let pageW, pageH;
    if (sizeKey === "fit") {
      // Fit to content — single long page
      const pxToPt = 0.75;
      pageW = 760 * pxToPt;
      pageH = (imgH / imgW) * pageW;
      const pdf = new jsPDF({ unit: "pt", format: [pageW, pageH] });
      pdf.addImage(imgData, "PNG", 0, 0, pageW, pageH);
      pdf.save(`CyberWeb_Report_${report.id}.pdf`);
    } else {
      const [pw, ph] = PAGE_SIZES[sizeKey];
      pageW = pw;
      pageH = ph;
      const margin = 30;
      const usableW = pageW - margin * 2;
      const usableH = pageH - margin * 2;
      const scaledH = (imgH / imgW) * usableW;
      const totalPages = Math.ceil(scaledH / usableH);

      const pdf = new jsPDF({ unit: "pt", format: [pageW, pageH] });

      for (let p = 0; p < totalPages; p++) {
        if (p > 0) pdf.addPage();
        const srcY = p * (usableH / (scaledH / imgH));
        const srcSliceH = usableH / (scaledH / imgH);

        // Create a slice canvas for this page
        const sliceCanvas = document.createElement("canvas");
        sliceCanvas.width = imgW;
        sliceCanvas.height = Math.min(srcSliceH, imgH - srcY);
        const ctx = sliceCanvas.getContext("2d");
        ctx.drawImage(canvas, 0, srcY, imgW, sliceCanvas.height, 0, 0, imgW, sliceCanvas.height);

        const sliceData = sliceCanvas.toDataURL("image/png");
        const sliceRenderedH = (sliceCanvas.height / imgW) * usableW;
        pdf.addImage(sliceData, "PNG", margin, margin, usableW, sliceRenderedH);
      }

      pdf.save(`CyberWeb_Report_${report.id}.pdf`);
    }
  } catch (err) {
    console.error("PDF generation error:", err);
    alert("Failed to generate PDF. Please try again.");
  } finally {
    btn.classList.remove("loading");
  }
}

/* ---------- Generate JPG ---------- */
async function generateJpgReport() {
  const btn = document.getElementById("export-download-btn");
  btn.classList.add("loading");

  try {
    const sections = getSelectedSections();
    const dom = buildReportDom(report, sections);

    dom.style.position = "fixed";
    dom.style.left = "-9999px";
    dom.style.top = "0";
    document.body.appendChild(dom);

    await new Promise((r) => setTimeout(r, 200));

    const canvas = await html2canvas(dom, {
      scale: 2,
      useCORS: true,
      backgroundColor: getExTheme().bg,
      logging: false,
    });

    document.body.removeChild(dom);

    // Download as JPG
    const link = document.createElement("a");
    link.download = `CyberWeb_Report_${report.id}.jpg`;
    link.href = canvas.toDataURL("image/jpeg", 0.92);
    link.click();
  } catch (err) {
    console.error("JPG generation error:", err);
    alert("Failed to generate JPG. Please try again.");
  } finally {
    btn.classList.remove("loading");
  }
}

/* ---------- Main dispatch ---------- */
async function startExport() {
  const format = getSelectedFormat();
  if (format === "jpg") {
    await generateJpgReport();
  } else {
    await generatePdfReport();
  }
}

/* ---------- Live Preview (always visible) ---------- */
let _previewDebounce = null;

function updateExportPreview() {
  const inner = document.getElementById("export-preview-inner");
  if (!inner) return;

  // Accessing global `report` variable from report.html's inline script
  if (typeof report === "undefined") return;

  const sections = getSelectedSections();
  const dom = buildReportDom(report, sections);

  // Clear previous preview and insert new one
  inner.innerHTML = "";
  inner.appendChild(dom);

  adjustPreviewScale();
}

function adjustPreviewScale() {
  const viewport = document.getElementById("export-preview-viewport");
  const inner = document.getElementById("export-preview-inner");
  if (!viewport || !inner || !inner.firstChild) return;

  // Reset inner styles to let it flow naturally first
  inner.style.transform = "none";
  inner.style.width = "auto";
  inner.style.height = "auto";

  const availableWidth = viewport.clientWidth;
  const scale = availableWidth / 760;

  const child = inner.firstChild;
  child.style.transformOrigin = "top left";
  child.style.transform = `scale(${scale})`;

  // Set the container size so the scrollbar reflects the scaled height perfectly
  inner.style.width = `${availableWidth}px`;
  inner.style.height = `${child.offsetHeight * scale}px`;
}

// Re-adjust scale when window resizes
window.addEventListener("resize", () => {
  if (document.getElementById("export-overlay").classList.contains("open")) {
    adjustPreviewScale();
  }
});

function schedulePreviewUpdate() {
  clearTimeout(_previewDebounce);
  _previewDebounce = setTimeout(updateExportPreview, 150);
}

/* Attach checkbox listeners for live preview refresh */
document.addEventListener("DOMContentLoaded", () => {
  const checkboxIds = ["ex-basics", "ex-scan", "ex-intel", "ex-screenshots", "ex-aiinsights", "ex-security", "ex-behaviour"];
  checkboxIds.forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", schedulePreviewUpdate);
  });
});
