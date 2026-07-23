/* ============================================================
   Shared behaviour: theme, mobile drawer, ribbon, icons.
   ============================================================ */

/* ---- Theme ---- */
(function () {
  const saved = localStorage.getItem("sw-theme");
  if (saved === "light") document.documentElement.setAttribute("data-theme", "light");
})();

function toggleTheme() {
  const el = document.documentElement;
  const next = el.getAttribute("data-theme") === "light" ? "dark" : "light";
  if (next === "light") el.setAttribute("data-theme", "light");
  else el.removeAttribute("data-theme");
  localStorage.setItem("sw-theme", next);
}

/* ---- Mobile drawer ---- */
function toggleDrawer(open) {
  const d = document.getElementById("drawer");
  if (!d) return;
  if (open === undefined) d.classList.toggle("open");
  else d.classList.toggle("open", open);
}

/* ---- Ribbon (sidebar) pin/expand toggle ----
   .ribbon.expanded is already fully styled in style.css (width, labels) -
   it was only ever reachable via :hover. This makes it a persistent,
   click-to-pin state (touch devices have no hover). */
function toggleRibbon() {
  const r = document.getElementById("ribbon");
  if (!r) return;
  r.classList.toggle("expanded");
}

/* ---- Ribbon "Menu" dropdown ----
   Appended to document.body (not nested in .ribbon) because .ribbon has
   overflow:hidden for its width transition, which would silently clip
   any dropdown rendered as its descendant. */
function toggleRibMenu(e) {
  const existing = document.getElementById("rib-menu-dropdown");
  if (existing) { existing.remove(); return; }
  if (!e) return;

  const btn = e.currentTarget;
  const rect = btn.getBoundingClientRect();
  const pinned = document.getElementById("ribbon").classList.contains("expanded");

  const dd = document.createElement("div");
  dd.id = "rib-menu-dropdown";
  dd.style.cssText = `
    position:fixed; top:${rect.top}px; left:${rect.right + 10}px;
    min-width:200px; background:var(--panel); border:1px solid var(--border);
    border-radius:var(--radius); box-shadow:0 12px 32px rgba(0,0,0,0.4);
    z-index:200; overflow:hidden; font-family:var(--font-body);
  `;
  dd.innerHTML = `
    <button onclick="toggleRibbon(); toggleRibMenu();" style="display:block;width:100%;text-align:left;padding:12px 16px;background:transparent;border:none;color:var(--text);font-size:0.9rem;cursor:pointer">
      ${pinned ? "Unpin sidebar" : "Pin sidebar open"}
    </button>
  `;
  document.body.appendChild(dd);

  // Attached after this click finishes bubbling, so the same click that
  // opened the menu doesn't immediately close it again.
  setTimeout(() => document.addEventListener("click", closeRibMenuOnOutsideClick, { once: true }), 0);
}

function closeRibMenuOnOutsideClick(e) {
  const dd = document.getElementById("rib-menu-dropdown");
  if (dd && !dd.contains(e.target)) dd.remove();
}

/* ---- SVG icon library (inline, no deps) ---- */
const ICONS = {
  logo: '<svg fill="#000000" width="800px" height="800px" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg"/></svg>',
  dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>',
  scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>',
  threat: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 L20 6 v6 c0 5-4 8-8 10 C8 20 4 17 4 12 V6 Z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>',
  traffic: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3 8 4-16 3 8h4"/></svg>',
  assets: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/></svg>',
  logs: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h13"/><path d="M8 12h13"/><path d="M8 18h13"/><circle cx="3" cy="6" r="1"/><circle cx="3" cy="12" r="1"/><circle cx="3" cy="18" r="1"/></svg>',
  report: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 15h6"/><path d="M9 11h2"/></svg>',
  settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/></svg>',
  theme: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  menu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M3 12h18M3 18h18"/></svg>',
  flag: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>',
  download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
  upload: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 L20 6 v6 c0 5-4 8-8 10 C8 20 4 17 4 12 V6 Z"/></svg>',
  globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20a15 15 0 0 1 0-20"/></svg>',
  bolt: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 3 14h7l-1 8 10-12h-7z"/></svg>',
  eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  email: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 6-10 7L2 6"/></svg>',
};

function icon(name) { return ICONS[name] || ""; }

/* Inject icons into any [data-icon] element */
function hydrateIcons() {
  document.querySelectorAll("[data-icon]").forEach((el) => {
    const n = el.getAttribute("data-icon");
    if (ICONS[n]) el.innerHTML = ICONS[n];
  });
}

/* ---- Ribbon markup (shared by app pages) ---- */
function renderRibbon(active) {
  const items = [
    { id: "home", label: "Homepage", href: "index.html", icon: "globe" },
    { id: "dashboard", label: "Dashboard", href: "dashboard.html", icon: "dashboard" },
    { id: "scan", label: "New Scan", href: "scan.html", icon: "scan" },
    { id: "report", label: "Reports", href: "report.html", icon: "report" },
    { id: "email", label: "Email", href: "email.html", icon: "email" },
  ];
  const links = items
    .map(
      (it) =>
        `<a class="rib-item ${it.id === active ? "active" : ""}" href="${it.href}" title="${it.label}">${icon(it.icon)}<span class="label">${it.label}</span></a>`
    )
    .join("");
  return `
    <button class="rib-item" onclick="toggleRibMenu(event)" title="Menu" style="margin-bottom:6px">${icon("menu")}<span class="label">Menu</span></button>
    <a class="rib-logo" href="index.html" title="Home">${icon("logo")}</a>
    ${links}
    <div class="rib-spacer"></div>
    <a class="rib-item ${"settings" === active ? "active" : ""}" href="settings.html" title="Settings">${icon("settings")}<span class="label">Settings</span></a>
  `;
}

/* Public top nav */
function renderTopbar(active) {
  const links = [
    { label: "Home", href: "index.html", id: "home" },
    { label: "Scan", href: "scan.html", id: "scan" },
    { label: "Dashboard", href: "dashboard.html", id: "dashboard" },
    { label: "Report", href: "report.html", id: "report" },
  ];
  return `
  <div class="brand">
    <span class="logo">${icon("logo")}</span>
    <span class="brand-name">CyberWeb</span>
  </div>
  <nav class="top-links">
    ${links.map((l) => `<a href="${l.href}" class="${l.id === active ? "active" : ""}">${l.label}</a>`).join("")}
    <a href="auth.html">Login</a>
  </nav>
  <div class="top-right-actions">
    <button class="icon-btn" onclick="toggleTheme()" title="Toggle theme" data-icon="theme"></button>
    <button class="menu-pill" onclick="toggleDrawer(true)">Menu <span class="bars"><span></span><span></span></span></button>
  </div>
  `;
}

function renderDrawer(active) {
  const links = [
    { label: "Home", href: "index.html" },
    { label: "Scan", href: "scan.html" },
    { label: "Dashboard", href: "dashboard.html" },
    { label: "Report", href: "report.html" },
    { label: "Login / Sign up", href: "auth.html" },
  ];
  return `
  <div class="drawer-panel">
    <button class="drawer-close" onclick="toggleDrawer(false)" aria-label="Close">&times;</button>
    ${links.map((l) => `<a href="${l.href}" onclick="toggleDrawer(false)">${l.label}</a>`).join("")}

  </div>`;
}

/* Init on every page */
document.addEventListener("DOMContentLoaded", () => {
  const active = document.body.getAttribute("data-page") || "";

  const tb = document.getElementById("topbar");
  if (tb) tb.innerHTML = renderTopbar(active);

  const dr = document.getElementById("drawer");
  if (dr) dr.innerHTML = renderDrawer(active);

  const rb = document.getElementById("ribbon");
  if (rb) rb.innerHTML = renderRibbon(active);

  hydrateIcons();
});

// slider for tabs new effect

const slider = document.querySelector(".tab-slider");

function moveSlider(btn) {
  if (!slider || !btn) return;
  const container = btn.closest(".tabs");
  const containerRect = container.getBoundingClientRect();
  const btnRect = btn.getBoundingClientRect();
  const offset = btnRect.left - containerRect.left - parseFloat(getComputedStyle(container).paddingLeft);

  slider.style.width = btnRect.width + "px";
  slider.style.transform = `translateX(${offset}px)`;
}

window.addEventListener("load", () => {

  moveSlider(document.querySelector(".tab.active"));

});

window.addEventListener("resize", () => {

  moveSlider(document.querySelector(".tab.active"));

});
