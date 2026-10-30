// This isolated-world bridge is restricted to the configured dashboard origin.
// The analyst must explicitly connect from Settings; tokens never enter a URL.
"use strict";
(() => {
  const allowedOrigin = new URL(SCYTHE_CONFIG.API_BASE_URL).origin;
  if (location.origin !== allowedOrigin || !location.pathname.startsWith("/dashboard/")) return;
  const JWT_REGEX = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
  window.addEventListener("message", event => {
    if (event.source !== window || event.origin !== allowedOrigin || !event.data) return;
    if (event.data.type === "SCYTHE_AUTH_CLEAR") {
      chrome.storage.local.remove(["scythe_token", "scythe_email"]);
    }
    if (event.data.type !== "SCYTHE_AUTH_CONNECT") return;
    const token = event.data.token;
    if (typeof token !== "string" || token.length > 16384 || !JWT_REGEX.test(token)) return;
    const email = String(event.data.email || "").slice(0, 320);
    chrome.storage.local.set({ scythe_token: token, scythe_email: email }, () => {
      if (!chrome.runtime.lastError) window.postMessage({ type: "SCYTHE_AUTH_CONNECTED" }, allowedOrigin);
    });
  });
})();
