/* ============================================================
   Mock / simulated data engine.
   Generates believable scan reports and dashboard feeds.
   ============================================================ */

const SAMPLE_DOMAINS = [
  "secure-login-paypa1.com", "update-account-verify.net", "microsoft-support.help",
  "amaz0n-delivery.info", "bankofamerica-alert.co", "netflix-billing-update.tv",
  "dropbox-sharedfile.link", "apple-id-locked.support", "chase-verify-now.com",
  "office365-signin.app", "coinbase-wallet-sync.io", "linkedin-jobalert.click",
];

const SAFE_DOMAINS = [
  "github.com", "wikipedia.org", "cloudflare.com", "vercel.com", "mozilla.org",
];

const THREAT_TYPES = ["Phishing", "Malware", "Credential Harvesting", "Typosquatting", "Spoofing", "Suspicious Redirect"];

function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function pick(arr) { return arr[rand(0, arr.length - 1)]; }
function uid() { return Math.random().toString(36).slice(2, 10); }

function escapeXml(s) {
  return String(s).replace(/[<>&'"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c]));
}

/* Generates a lightweight browser-chrome mockup as an inline SVG data URI,
   standing in for a real sandbox screenshot capture. Used only by the
   Sandbox tab's Screenshot Capture panel. */
function screenshotDataUri(host, isSafe, tall) {
  const w = 640, h = tall ? 900 : 400;
  const bg = isSafe ? "#111a2e" : "#241318";
  const barColor = isSafe ? "#5b8cff" : "#ef5468";
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
    <rect width="${w}" height="${h}" fill="${bg}"/>
    <rect width="${w}" height="34" fill="#0d1220"/>
    <circle cx="18" cy="17" r="5" fill="#ef5468"/>
    <circle cx="36" cy="17" r="5" fill="#f0a857"/>
    <circle cx="54" cy="17" r="5" fill="#3ea6ff"/>
    <rect x="80" y="8" width="${w - 160}" height="18" rx="9" fill="#1a2337"/>
    <text x="90" y="21" font-family="monospace" font-size="11" fill="#8992a9">${escapeXml(host)}</text>
    <rect x="40" y="70" width="${w - 80}" height="14" rx="4" fill="${barColor}" opacity="0.85"/>
    <rect x="40" y="100" width="${(w - 80) * 0.7}" height="10" rx="4" fill="#2a3450"/>
    <rect x="40" y="122" width="${(w - 80) * 0.5}" height="10" rx="4" fill="#2a3450"/>
    <rect x="40" y="160" width="180" height="42" rx="8" fill="${barColor}"/>
    <text x="130" y="186" font-family="sans-serif" font-size="13" fill="#0a0e17" text-anchor="middle">${isSafe ? "Continue" : "Verify Now"}</text>
  </svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

/* Build one analysis report for a given URL */
function generateReport(url) {
  let host = url;
  try { host = new URL(url.includes("://") ? url : "https://" + url).hostname; } catch (e) { }

  const isSafe = SAFE_DOMAINS.some((d) => host.includes(d));
  const legitimacy = isSafe ? rand(88, 99) : rand(6, 44);
  const aiConfidence = rand(94, 999) / 10;
  const verdict = legitimacy >= 70 ? "SAFE" : legitimacy >= 45 ? "SUSPICIOUS" : "MALICIOUS";

  const detected = isSafe
    ? []
    : Array.from({ length: rand(2, 4) }, () => pick(THREAT_TYPES)).filter((v, i, a) => a.indexOf(v) === i);

  // ---- Sandbox (dynamic/behavioral analysis) — same field set as the
  // previous report's Sandbox tab (Page & TLS info, Security & Redirects,
  // request/popup/download stats, full Behaviour Summary signals).
  const sandboxCertPresent = isSafe ? true : Math.random() > 0.3;
  const sandboxBrandMatch = isSafe
    ? null
    : (Math.random() > 0.4
      ? { brand: pick(["microsoft", "paypal", "amazon", "apple", "chase", "netflix", "dropbox"]), similarity: +(rand(75, 99) / 100).toFixed(2) }
      : null);
  const sandboxRedirects = Array.from({ length: isSafe ? rand(0, 1) : rand(1, 4) }, () => ({
    httpStatusCode: pick([301, 302, 307]),
    redirectUrl: `https://${pick(SAMPLE_DOMAINS)}/landing`,
  }));
  const sandboxDownloads = Array.from({ length: isSafe ? 0 : rand(0, 2) }, () => ({
    fileName: pick(["invoice.exe", "update.zip", "secure-doc.pdf.exe", "installer.msi", "statement.scr"]),
    fileSizeBytes: rand(20000, 4500000),
  }));
  const sandboxEvasionTechniques = ["Fingerprint Evasion", "Headless Browser Detection Bypass", "Delayed Payload Execution", "Right-Click Disable", "DevTools Detection Bypass", "IP Cloaking"]
    .slice(0, rand(2, 4))
    .map((name) => ({ name, flagged: isSafe ? false : Math.random() > 0.5 }));
  const sandboxPermissionRequests = isSafe
    ? []
    : ["geolocation", "notifications", "camera", "microphone"].filter(() => Math.random() > 0.65);

  return {
    id: uid(),
    url: url,
    host: host,
    scannedAt: new Date().toLocaleString(),
    legitimacy,
    aiConfidence,
    verdict,
    riskScore: 100 - legitimacy,
    detected,
    intel: {
      domain: pick(["NameCheap Inc", "GoDaddy LLC", "Porkbun", "Tucows", "Google Domains"]),
      age: `${rand(1, 60)} days`,
      confidence: `${rand(90, 99)}%`,
      ip: `${rand(11, 220)}.${rand(0, 255)}.${rand(0, 255)}.${rand(1, 254)}`,
      threat: isSafe ? 0 : rand(3, 9),
      expiration: `${rand(30, 365)} days`,

      reputation: isSafe ? "Safe" : "Unsafe",
      brandSimilarity: isSafe ? "No" : "Yes",
      fakeCharacters: isSafe ? "Not Detected" : "Detected",
      urlShortener: isSafe ? "No" : "Yes",
    },
    sandbox: {
      // Screenshot capture
      screenshots: {
        homepage: screenshotDataUri(host, isSafe, false),
        fullpage: screenshotDataUri(host, isSafe, true),
      },

      // Page & TLS info
      pageTitle: isSafe
        ? `${host} — Official Site`
        : pick(["Account Verification Required", "Sign in to your account", "Secure Login Portal", "Confirm Your Identity"]),
      finalUrl: `https://${host}/`,
      pageLanguage: pick(["en", "en-US", "en-GB", "es", "fr"]),
      domElementCount: rand(120, 2400),
      certificatePresent: sandboxCertPresent,
      certificateIssuer: sandboxCertPresent ? pick(["Let's Encrypt", "DigiCert Inc", "Sectigo", "Google Trust Services"]) : null,
      tlsVersion: sandboxCertPresent ? pick(["TLS 1.2", "TLS 1.3"]) : null,
      certificateIssued: sandboxCertPresent ? new Date(Date.now() - rand(5, 300) * 86400000).toLocaleDateString() : null,

      // Security & redirects
      securityHeadersPresent: isSafe
        ? "Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options"
        : pick(["None", "X-Content-Type-Options", "Strict-Transport-Security"]),
      brandImpersonationMatch: sandboxBrandMatch,
      qrCodeDetected: isSafe ? false : Math.random() > 0.85,
      cloakingDetected: isSafe ? false : Math.random() > 0.6,
      redirects: sandboxRedirects,

      // Stats
      totalRequestCount: rand(12, 180),
      thirdPartyDomainCount: isSafe ? rand(1, 5) : rand(6, 20),
      popupCount: isSafe ? 0 : rand(0, 3),
      downloads: sandboxDownloads,

      // Behaviour summary
      xhrRequestCount: rand(0, 40),
      websocketConnectionCount: isSafe ? 0 : rand(0, 2),
      fingerprintingApiCount: isSafe ? rand(0, 1) : rand(1, 6),
      newTabCount: isSafe ? 0 : rand(0, 2),
      clipboardReadAttempts: isSafe ? 0 : rand(0, 2),
      clipboardWriteAttempts: isSafe ? 0 : rand(0, 2),
      permissionRequests: sandboxPermissionRequests,
      passwordFieldCount: isSafe ? 0 : rand(1, 2),
      emailFieldCount: isSafe ? 0 : rand(1, 2),
      crossDomainFormCount: isSafe ? 0 : rand(0, 1),
      hiddenIframeCount: isSafe ? 0 : rand(0, 2),
      externalScriptCount: rand(0, 20),
      base64EncodedScriptCount: isSafe ? 0 : rand(0, 6),
      evasionTechniques: sandboxEvasionTechniques,

      verdict: verdict,
    },
  };
}

/* Dashboard aggregate data */
function generateDashboard() {
  const alerts = Array.from({ length: 12 }, () => {
    const malicious = Math.random() > 0.45;
    const host = malicious ? pick(SAMPLE_DOMAINS) : pick(SAFE_DOMAINS);
    const sev = malicious ? pick(["danger", "warn"]) : "ok";
    return {
      host,
      type: malicious ? pick(THREAT_TYPES) : "Clean scan",
      sev,
      time: `${rand(1, 59)}m ago`,
    };
  });

  const flagged = SAMPLE_DOMAINS.map((d) => ({
    host: d, type: pick(THREAT_TYPES), risk: rand(70, 99),
  }));

  return {
    threats: rand(18, 64),
    riskScore: rand(42, 88),
    flagged: flagged.length,
    scans: rand(120, 480),
    alerts,
    flaggedList: flagged,
  };
}

/* Persist last report so report.html can read it after a scan */
function saveLastReport(report) {
  try { sessionStorage.setItem("sw-last-report", JSON.stringify(report)); } catch (e) { }
}
function loadLastReport() {
  try {
    const r = sessionStorage.getItem("sw-last-report");
    return r ? JSON.parse(r) : null;
  } catch (e) { return null; }
}

/* ============================================================
   Email tab — mock data engine.
   Every field name below matches a column name from the SQL
   schema exactly (snake_case, 1:1). Grouping keys (recipients,
   authentication, received_chain, etc.) correspond to the source
   table. No fields are invented beyond what the schema defines.

   Corrections applied vs. the schema as originally pasted:
     - emails: removed trailing comma after created_at (syntax error)
     - email_authentication: added missing comma before alignment_status (syntax error)
     - attachment_count.attavhment_count -> attachment_count (typo)

   Note: message_user_map.user_id is carried through as a raw UUID.
   No `users` table was provided in the schema, so it cannot be
   resolved to a name/email here.

   Relies on rand(), pick(), uid(), SAMPLE_DOMAINS, SAFE_DOMAINS,
   THREAT_TYPES already defined globally by js/mock.js — load that
   file before this one.
   ============================================================ */

function mockUUID() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function mockSha256() {
  let out = "";
  for (let i = 0; i < 64; i++) out += "0123456789abcdef"[rand(0, 15)];
  return out;
}

const EMAIL_SUBJECTS_UNSAFE = [
  "Your account has been suspended",
  "Action required: verify your identity",
  "Invoice #48213 — payment overdue",
  "Unusual sign-in activity detected",
  "Confirm your password reset",
  "Your package could not be delivered",
];
const EMAIL_SUBJECTS_SAFE = [
  "Your weekly summary is ready",
  "Receipt for your recent order",
  "Meeting notes from today",
  "Welcome to the team",
  "Your subscription was renewed",
];
const FROM_LOCAL_PARTS = ["billing", "support", "security", "no-reply", "accounts", "admin", "alerts"];
const DISPLAY_NAMES = ["Billing Team", "Account Security", "Support Desk", "IT Administrator", "No Reply", "Customer Care"];
const RECIPIENT_DOMAINS = ["corp-mail.com", "example.org", "myinbox.com"];
const HEADER_SAMPLES = ["MIME-Version", "Content-Type", "X-Mailer", "X-Originating-IP", "Message-ID", "Auto-Submitted"];
const MIME_TYPES = ["application/pdf", "application/zip", "image/png", "application/vnd.ms-excel", "application/octet-stream"];
const FILE_EXTENSIONS = { "application/pdf": "pdf", "application/zip": "zip", "image/png": "png", "application/vnd.ms-excel": "xls", "application/octet-stream": "exe" };
const COUNTRIES = ["United States", "Netherlands", "Russia", "Germany", "Nigeria", "Vietnam", "Romania"];

function generateEmailRecord() {
  const isSafe = Math.random() > 0.55;
  const domain = isSafe ? pick(SAFE_DOMAINS) : pick(SAMPLE_DOMAINS);
  const message_id = mockUUID();
  const from_address = `${pick(FROM_LOCAL_PARTS)}@${domain}`;
  const sentDate = new Date(Date.now() - rand(0, 30) * 86400000 - rand(0, 86399) * 1000);
  const spoofed = !isSafe && Math.random() > 0.45;
  const returnPathDomain = spoofed ? pick(SAMPLE_DOMAINS) : domain;

  // ---- recipients ----
  const recipientTypes = ["TO", ...(Math.random() > 0.5 ? ["CC"] : []), ...(Math.random() > 0.75 ? ["BCC"] : [])];
  const recipients = recipientTypes.map((recipient_type) => ({
    message_id,
    recipient_type,
    recipient_address: `${pick(["alice", "bob", "priya", "devon", "team"])}@${pick(RECIPIENT_DOMAINS)}`,
  }));

  // ---- email_reply_to ----
  const reply_to_domain = spoofed ? pick(SAMPLE_DOMAINS) : domain;
  const reply_to = {
    message_id,
    reply_to: `${pick(FROM_LOCAL_PARTS)}@${reply_to_domain}`,
    reply_to_domain,
  };

  // ---- email_authentication ----
  const spf_result = isSafe ? "pass" : pick(["fail", "none", "neutral"]);
  const dkim_result = isSafe ? "pass" : pick(["fail", "none"]);
  const dmarc_result = isSafe ? "pass" : pick(["fail", "none"]);
  const authentication = {
    auth_id: mockUUID(),
    message_id,
    spf_result,
    spf_domain: domain,
    dkim_result,
    dkim_domain: domain,
    dkim_selector: pick(["default", "google", "selector1", "s1"]),
    dmarc_result,
    dmarc_policy: pick(["none", "quarantine", "reject"]),
    overall_auth_result: isSafe ? "pass" : pick(["fail", "partial", "neutral", "none"]),
    alignment_status: isSafe ? "aligned" : pick(["misaligned", "partial", "unknown"]),
  };

  // ---- message_user_map ----
  const user_map = { user_id: mockUUID(), message_id };

  // ---- received_chain / received_hops ----
  const hopCount = rand(2, 5);
  const received_hops = Array.from({ length: hopCount }, (_, idx) => {
    const hop_number = idx + 1;
    return {
      message_id,
      hop_number,
      received_from: `mail-relay-${hop_number}.${pick(SAMPLE_DOMAINS.concat(SAFE_DOMAINS))}`,
      received_by: `mx${hop_number}.${domain}`,
      received_with: pick(["ESMTP", "ESMTPS", "SMTP"]),
      received_id: mockUUID(),
      received_for: from_address,
      received_timestamp: new Date(sentDate.getTime() - (hopCount - hop_number) * 60000).toISOString(),
    };
  });
  const received_chain = {
    message_id,
    hop_number: hopCount,
    received_count: hopCount,
    originating_ip: `${rand(11, 220)}.${rand(0, 255)}.${rand(0, 255)}.${rand(1, 254)}`,
    sender_hostname: `mail.${domain}`,
    sender_country: isSafe ? pick(["United States", "Germany", "Netherlands"]) : pick(COUNTRIES),
    sender_asn: rand(1000, 65000),
    reverse_dns: Math.random() > 0.3 ? `mail.${domain}` : null,
  };

  // ---- email_headers ----
  const headers = HEADER_SAMPLES.map((header_name) => ({
    message_id,
    header_name,
    header_value:
      header_name === "Message-ID" ? `<${uid()}@${domain}>` :
      header_name === "Content-Type" ? "multipart/mixed; boundary=\"----=_Part\"" :
      header_name === "MIME-Version" ? "1.0" :
      header_name === "X-Originating-IP" ? `[${rand(11,220)}.${rand(0,255)}.${rand(0,255)}.${rand(1,254)}]` :
      header_name === "X-Mailer" ? pick(["Outlook 16.0", "PHPMailer 6.8", "Postfix", "Sendmail 8.15"]) :
      "no",
  }));

  // ---- email_domains ----
  const domains_info = {
    message_id,
    sender_domain: domain,
    return_path_domain: returnPathDomain,
    message_id_domain: domain,
    dkim_domain: domain,
  };

  // ---- domains (master) ----
  const domain_master = {
    email_domain_name: domain,
    dnssec_enabled: isSafe ? true : Math.random() > 0.7,
    mx_records: `10 mx1.${domain}; 20 mx2.${domain}`,
  };

  // ---- impersonation ----
  const impersonation = {
    message_id,
    typo_squatting: spoofed && Math.random() > 0.4,
    display_name_spoof: spoofed && Math.random() > 0.5,
    spoofing_detected: spoofed,
  };

  // ---- attachments / attachment_count ----
  const attachmentN = isSafe ? rand(0, 1) : rand(0, 3);
  const attachments = Array.from({ length: attachmentN }, () => {
    const mime_type = pick(MIME_TYPES);
    const file_extension = FILE_EXTENSIONS[mime_type];
    const malware_detected = !isSafe && Math.random() > 0.6;
    return {
      attachment_id: mockUUID(),
      message_id,
      attachment_name: `${pick(["invoice", "statement", "document", "update", "attachment"])}.${file_extension}`,
      attachment_size: rand(4000, 4500000),
      file_extension,
      mime_type,
      sha256_hash: mockSha256(),
      malware_detected,
      macro_present: file_extension === "xls" ? Math.random() > 0.5 : false,
      content_disposition: "attachment",
      is_inline: false,
      attachment_password_protected: Math.random() > 0.85,
    };
  });
  const attachment_count = { message_id, attachment_count: attachments.length };

  // ---- email_content ----
  const content = {
    message_id,
    body_text: isSafe
      ? "Hi, please find the requested information attached. Let us know if you have any questions."
      : "Your account requires immediate verification. Click the link below to confirm your details or your access will be suspended.",
    html_body: null,
    language: pick(["en", "en-US", "en-GB", "es", "fr"]),
    urgency_score: isSafe ? rand(2, 20) / 10 : rand(50, 98) / 10,
    credential_theft_score: isSafe ? rand(0, 15) / 10 : rand(40, 95) / 10,
    financial_score: isSafe ? rand(0, 10) / 10 : rand(20, 90) / 10,
    spam_score: isSafe ? rand(0, 20) / 10 : rand(30, 99) / 10,
    link_mentioned: !isSafe || Math.random() > 0.5,
    homoglyph_in_subject_or_body: spoofed && Math.random() > 0.5,
    embedded_tracking_pixel_count: isSafe ? 0 : rand(0, 3),
  };

  // ---- extracted_urls ----
  const urlN = isSafe ? rand(0, 1) : rand(1, 4);
  const extracted_urls = Array.from({ length: urlN }, (_, idx) => ({
    message_id,
    url_sequence: idx + 1,
    extracted_url: `https://${pick(SAMPLE_DOMAINS)}/${pick(["verify", "login", "secure", "account", "confirm"])}`,
  }));

  return {
    message_id,
    from_address,
    display_name: pick(DISPLAY_NAMES),
    return_path: `bounce@${returnPathDomain}`,
    subject: isSafe ? pick(EMAIL_SUBJECTS_SAFE) : pick(EMAIL_SUBJECTS_UNSAFE),
    sent_at: sentDate.toLocaleString(),
    thread_id: uid(),
    recipient_count: recipients.length,
    created_at: new Date(sentDate.getTime() + 2000).toLocaleString(),

    recipients,
    reply_to,
    authentication,
    user_map,
    received_chain,
    received_hops,
    headers,
    domains_info,
    domain_master,
    impersonation,
    attachments,
    attachment_count,
    content,
    extracted_urls,

    _isSafe: isSafe, // UI-only convenience flag, not a schema field — used solely for list-view badge coloring
  };
}

function generateEmailList(count) {
  return Array.from({ length: count || 10 }, generateEmailRecord)
    .sort((a, b) => new Date(b.sent_at) - new Date(a.sent_at));
}