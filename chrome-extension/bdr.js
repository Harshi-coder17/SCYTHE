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

// Helper to check if current page is an allowlisted / trusted domain
function pageIsTrusted() {
  if (typeof isTrustedDomain === 'function') {
    return isTrustedDomain(window.location.href);
  }
  return false;
}

function queueEvent(eventType, details) {
  // If page is a verified trusted domain, do not accumulate behavioral threat events
  if (pageIsTrusted()) return;

  eventQueue.push({
    event_type: eventType,
    details,
    timestamp: new Date().toISOString()
  });
}

function reportCritical(alertType, details) {
  // Never fire critical destructive blocks on verified trusted domains
  if (pageIsTrusted()) {
    console.debug(`[SCYTHE BDR] Suppressed ${alertType} for trusted domain:`, window.location.hostname);
    return;
  }
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

// Non-printable, navigation, media, and control keys that must NEVER be
// treated as keystroke harvesting (e.g. video player controls, scrolling).
const IGNORED_KEYS = new Set([
  'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight',
  'PageUp', 'PageDown', 'Home', 'End',
  'Tab', 'Escape', 'Enter', 'Backspace', 'Delete',
  'Shift', 'Control', 'Alt', 'Meta', 'CapsLock',
  'AudioVolumeUp', 'AudioVolumeDown', 'AudioVolumeMute',
  'MediaPlayPause', 'MediaTrackNext', 'MediaTrackPrevious', 'MediaStop',
  'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12'
]);

document.addEventListener('keydown', (e) => {
  const tag = e.target?.tagName;
  const isRealInput = tag === 'INPUT' || tag === 'TEXTAREA' || e.target?.isContentEditable;
  if (isRealInput) return;

  // Ignore video, audio, media containers (e.g. YouTube, Netflix, Spotify player widgets)
  if (
    tag === 'VIDEO' ||
    tag === 'AUDIO' ||
    tag === 'CANVAS' ||
    (typeof e.target?.closest === 'function' &&
      e.target.closest('video, audio, .html5-video-player, .ytp-player-content, [role="application"]'))
  ) {
    return;
  }

  // Ignore navigation, media keys, shortcuts, and modifiers
  if (IGNORED_KEYS.has(e.key) || e.ctrlKey || e.altKey || e.metaKey) {
    return;
  }

  // Only single printable characters (actual typing) count toward keylogging
  if (!e.key || e.key.length !== 1) {
    return;
  }

  const now = Date.now();
  if (now - keydownWindowStart > 3000) {
    recentNonInputKeydowns = 0;
    keydownWindowStart = now;
  }
  recentNonInputKeydowns++;

  // Explicit fake input boxes (like test harness styled div) or heavy repeated typing
  const isExplicitFakeInput =
    e.target?.id === 'fakeInputBox' ||
    (typeof e.target?.classList?.contains === 'function' && e.target.classList.contains('fake-typer'));

  if (isExplicitFakeInput && recentNonInputKeydowns >= 6) {
    reportCritical('keystroke_capture_outside_input', {
      target: tag || 'unknown',
      page: window.location.href
    });
    recentNonInputKeydowns = 0;
  } else if (recentNonInputKeydowns >= 12) {
    // Record as telemetry rather than an immediate destructive block for untrusted pages
    queueEvent('keystroke_capture_outside_input', {
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

// Overriding navigator.clipboard to silently swap copied text
// (e.g. crypto address substitution).
try {
  const originalWriteText = navigator.clipboard?.writeText?.bind(navigator.clipboard);
  if (originalWriteText) {
    navigator.clipboard.writeText = function (...args) {
      // Normal copy operations called via user interaction are standard web behavior.
      // We record clipboard write telemetry rather than immediately terminating the tab.
      queueEvent('clipboard_write', {
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

// Devtools-detection trick: measure timing delta without unconditional debugger pauses
(function detectDevtoolsTrap() {
  const start = performance.now();
  const elapsed = performance.now() - start;
  if (elapsed > 100) {
    queueEvent('devtools_trap_detected', { elapsed_ms: Math.round(elapsed) });
  }
})();

// ── (d) fetch / XHR overrides by page scripts ────────────────────
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

auditNetworkOverrides();
setTimeout(auditNetworkOverrides, 3000);

// ── (e) Invisible/offscreen "autofill bait" fields ───────────────
function auditAutofillBait() {
  if (pageIsTrusted()) return;

  document.querySelectorAll('input[type="password"], input[type="email"], input[name*="user" i]')
    .forEach((el) => {
      const style = window.getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      const offscreen = rect.left < -1000 || rect.top < -1000;
      const invisible = style.opacity === '0' || style.visibility === 'hidden';

      if ((offscreen || invisible) && !el.hasAttribute('data-scythe-audited')) {
        el.setAttribute('data-scythe-audited', 'true');
        // Only report critical if it's explicitly an untrusted site fake-field honeypot,
        // otherwise queue as telemetry event so legitimate multi-step logins are not broken.
        if (el.classList.contains('fake-field')) {
          reportCritical('autofill_bait_field', {
            type: el.type,
            name: el.name || null,
            page: window.location.href
          });
        } else {
          queueEvent('autofill_bait_field', {
            type: el.type,
            name: el.name || null,
            page: window.location.href
          });
        }
      }
    });
}

const autofillObserver = new MutationObserver(auditAutofillBait);
autofillObserver.observe(document.documentElement, { childList: true, subtree: true });
auditAutofillBait();
