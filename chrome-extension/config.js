// Set this single HTTPS origin for your deployment, then reload the extension.
// Local Compose defaults expose nginx at https://localhost:8443.
const SCYTHE_ORIGIN = "https://localhost:8443";

const TRUSTED_ALLOWLIST_DOMAINS = Object.freeze([
  "google.com",
  "youtube.com",
  "whatsapp.com",
  "facebook.com",
  "meta.com",
  "instagram.com",
  "twitter.com",
  "x.com",
  "linkedin.com",
  "reddit.com",
  "netflix.com",
  "chatgpt.com",
  "openai.com",
  "claude.ai",
  "discord.com",
  "spotify.com",
  "zoom.us",
  "telegram.org",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "github.com",
  "gitlab.com",
  "twitch.tv",
  "wikipedia.org",
  "yahoo.com",
  "bing.com",
  "duckduckgo.com"
]);

function isTrustedDomain(urlOrHostname) {
  if (!urlOrHostname) return false;
  try {
    let hostname = urlOrHostname;
    if (urlOrHostname.includes("://")) {
      hostname = new URL(urlOrHostname).hostname;
    }
    hostname = hostname.toLowerCase();
    return TRUSTED_ALLOWLIST_DOMAINS.some(
      (td) => hostname === td || hostname.endsWith("." + td)
    );
  } catch {
    return false;
  }
}

const SCYTHE_CONFIG = Object.freeze({
  API_BASE_URL: new URL(SCYTHE_ORIGIN).origin,
  DASHBOARD_URL: new URL("/dashboard/components/dashboard.html", SCYTHE_ORIGIN).href,
  TRUSTED_DOMAINS: TRUSTED_ALLOWLIST_DOMAINS,
  isTrustedDomain,
});
