// ============================================================
// SCYTHE — BDR (Browser Deception & Reconnaissance) Script
// Distinct from content.js:
//   content.js = DOM STRUCTURE audit (forms, iframes, URL shape)
//   bdr.js     = RUNTIME BEHAVIOR audit (event hijacking, clipboard,
//                devtools traps, eval usage, fetch/XHR overrides)
// Sends the same message types as content.js (BDR_EVENTS / BDR_CRITICAL)
// so background.js's handler treats both as interchangeable sources.
// ============================================================

const FLUSH_INTERVAL_MS = 5000;
let eventQueue = [];

function queueEvent(eventType, details) {
  eventQueue.push({
    event_type: eventType,
    details,
    timestamp: new Date().toISOString()
  });
}

function reportCritical(alertType, details) {
  chrome.runtime.sendMessage({ type: 'BDR_CRITICAL', alert_type: alertType, details });
}

function flush() {
  if (eventQueue.length === 0) return;
  const events = eventQueue;
  eventQueue = [];
  chrome.runtime.sendMessage({ type: 'BDR_EVENTS', events });
}

setInterval(flush, FLUSH_INTERVAL_MS);
window.addEventListener('beforeunload', flush);

// ── (a) Keystroke capture outside real <input> elements ─────────
// Fake login overlays sometimes render styled <div>s and attach
// keydown listeners to `document` or a container to build a string
// character-by-character, avoiding real form fields entirely.
let recentNonInputKeydowns = 0;
let keydownWindowStart = Date.now();

document.addEventListener('keydown', (e) => {
  const tag = e.target?.tagName;
  const isRealInput = tag === 'INPUT' || tag === 'TEXTAREA' || e.target?.isContentEditable;
  if (isRealInput) return;

  const now = Date.now();
  if (now - keydownWindowStart > 3000) {
    recentNonInputKeydowns = 0;
    keydownWindowStart = now;
  }
  recentNonInputKeydowns++;

  // A burst of "letter-like" keydowns landing outside any input field,
  // in a short window, is a strong signal of a fake-field keylogger.
  if (recentNonInputKeydowns >= 6) {
    reportCritical('keystroke_capture_outside_input', {
      target: tag || 'unknown',
      page: window.location.href
    });
    recentNonInputKeydowns = 0;
  }
}, true);

// ── (b) Clipboard hijacking ──────────────────────────────────────
['copy', 'paste', 'cut'].forEach((evtName) => {
  document.addEventListener(evtName, () => {
    queueEvent('clipboard_access', { event: evtName, page: window.location.href });
  }, true);
});

// Overriding navigator.clipboard itself (to silently swap copied text,
// e.g. crypto address substitution) is far more serious than a normal
// copy/paste event.
try {
  const originalWriteText = navigator.clipboard?.writeText?.bind(navigator.clipboard);
  if (originalWriteText) {
    navigator.clipboard.writeText = function (...args) {
      reportCritical('clipboard_write_intercepted', {
        page: window.location.href
      });
      return originalWriteText(...args);
    };
  }
} catch {
  // clipboard API unavailable in this context; ignore
}

// ── (c) DevTools / right-click blocking ─────────────────────────
document.addEventListener('contextmenu', (e) => {
  if (e.defaultPrevented) {
    queueEvent('context_menu_blocked', { page: window.location.href });
  }
}, true);

// Common devtools-detection trick: measure debugger pause duration
(function detectDevtoolsTrap() {
  const start = performance.now();
  // eslint-disable-next-line no-debugger
  debugger;
  const elapsed = performance.now() - start;
  if (elapsed > 100) {
    queueEvent('devtools_trap_detected', { elapsed_ms: Math.round(elapsed) });
  }
})();

// ── (d) fetch / XHR overrides by page scripts ────────────────────
// We can't see the page's JS globals directly (content scripts run in an
// isolated world), but we CAN detect the fingerprint left behind: if
// window.fetch or XMLHttpRequest.prototype.open no longer match native
// code, something on the page has monkey-patched them.
function looksOverridden(fn) {
  if (typeof fn !== 'function') return false;
  return !/\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn));
}

function auditNetworkOverrides() {
  try {
    if (looksOverridden(window.fetch)) {
      queueEvent('fetch_overridden', { page: window.location.href });
    }
    if (looksOverridden(XMLHttpRequest.prototype.open)) {
      queueEvent('xhr_overridden', { page: window.location.href });
    }
  } catch {
    // cross-origin restrictions or missing APIs; ignore
  }
}

// Check once at start, and again after a delay (some kits patch late)
auditNetworkOverrides();
setTimeout(auditNetworkOverrides, 3000);

// ── (e) Invisible/offscreen "autofill bait" fields ───────────────
// Fields positioned off-screen or with zero opacity, present purely to
// catch browser autofill (which doesn't respect visibility) and steal
// saved credentials without the user seeing a real form.
function auditAutofillBait() {
  document.querySelectorAll('input[type="password"], input[type="email"], input[name*="user" i]')
    .forEach((el) => {
      const style = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      const offscreen = rect.left < -1000 || rect.top < -1000;
      const invisible = style.opacity === '0' || style.visibility === 'hidden';

      if ((offscreen || invisible) && !el.hasAttribute('data-scythe-audited')) {
        el.setAttribute('data-scythe-audited', 'true');
        reportCritical('autofill_bait_field', {
          type: el.type,
          name: el.name || null,
          page: window.location.href
        });
      }
    });
}

const autofillObserver = new MutationObserver(auditAutofillBait);
autofillObserver.observe(document.documentElement, { childList: true, subtree: true });
auditAutofillBait();