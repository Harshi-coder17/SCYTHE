// ============================================================
// SCYTHE Extension — Central Configuration
// ============================================================
//
// ► HOW TO CONFIGURE FOR YOUR DEPLOYMENT:
//   1. Set API_BASE_URL to your deployed backend server URL
//   2. Set DASHBOARD_URL to where the SCYTHE dashboard is hosted
//   3. Reload the extension in Chrome (chrome://extensions → ↺)
//
// Local development:
//   API_BASE_URL  = "http://localhost:8000"
//   DASHBOARD_URL = "http://localhost:8000/dashboard"
//
// Production (example):
//   API_BASE_URL  = "https://scythe.yourcompany.com"
//   DASHBOARD_URL = "https://scythe.yourcompany.com/dashboard"
// ============================================================

const SCYTHE_CONFIG = Object.freeze({
  API_BASE_URL:  "http://localhost:8000",
  DASHBOARD_URL: "http://localhost:8000/dashboard",
});
