// Set this single HTTPS origin for your deployment, then reload the extension.
// Local Compose defaults expose nginx at https://localhost:8443.
const SCYTHE_ORIGIN = "https://localhost:8443";
const SCYTHE_CONFIG = Object.freeze({
  API_BASE_URL: new URL(SCYTHE_ORIGIN).origin,
  DASHBOARD_URL: new URL("/dashboard/components/dashboard.html", SCYTHE_ORIGIN).href,
});
