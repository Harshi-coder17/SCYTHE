# SCYTHE Architecture, OSINT & Deep Detection Improvement Roadmap

> **Deep OSINT, Academic Literature Review (2024–2026), and Platform Enhancement Specifications**  
> Benchmarked against recent publications from USENIX Security (*Phishpedia*, *PhishIntention*), AAAI-25 (*PhishAgent*), APWG eCrime 2024 (*Multimodal LLMs for Phishing*), IEEE TIFS, and contemporary threat actor evasions (AiTM, Quishing, Browser-in-the-Browser, WOFF Font Ciphers, Canvas Cloaking).

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Threat Landscape Gaps & Evasion Defenses](#2-threat-landscape-gaps--evasion-defenses)
   - [2.1 Quishing (QR Code Phishing) in Email & Attachments](#21-quishing-qr-code-phishing-in-email--attachments)
   - [2.2 Browser-in-the-Browser (BitB) & Dynamic DOM Overlays](#22-browser-in-the-browser-bitb--dynamic-dom-overlays)
   - [2.3 Reverse-Proxy AiTM (Evilginx3, Modlishka) TLS Fingerprinting](#23-reverse-proxy-aitm-evilginx3-modlishka-tls-fingerprinting)
   - [2.4 ASCII & Latin Zero-Day Homoglyph / Confusable Evasions](#24-ascii--latin-zero-day-homoglyph--confusable-evasions)
   - [2.5 WOFF Font Substitution Ciphers & HTML5 Canvas Rendering](#25-woff-font-substitution-ciphers--html5-canvas-rendering)
   - [2.6 Captcha Wall & Cloudflare Turnstile Cloaking Shields](#26-captcha-wall--cloudflare-turnstile-cloaking-shields)
3. [Machine Learning & Model Architecture Upgrades](#3-machine-learning--model-architecture-upgrades)
   - [3.1 Visual Head: MobileCLIP S0 vs. Decoupled Logo Siamese (DINOv2)](#31-visual-head-mobileclip-s0-vs-decoupled-logo-siamese-dinov2)
   - [3.2 URL Classifier: 18-Feature Contract Expansion to 28+ Features (PhiUSIIL)](#32-url-classifier-18-feature-contract-expansion-to-28-features-phiusiil)
   - [3.3 LightGBM vs. TabNet / Transformers for Line-Rate Scanning](#33-lightgbm-vs-tabnet--transformers-for-line-rate-scanning)
   - [3.4 Multimodal LLMs (MLLMs) & Agentic Triage (eCrime 2024 / AAAI 2025)](#34-multimodal-llms-mllms--agentic-triage-ecrime-2024--aaai-2025)
4. [External Threat Intelligence & OSINT Ingestion](#4-external-threat-intelligence--osint-ingestion)
   - [4.1 Tier-0 Redis Cache Ingestion (URLhaus, OpenPhish, PhishTank)](#41-tier-0-redis-cache-ingestion-urlhaus-openphish-phishtank)
   - [4.2 Certificate Transparency (CT Log) Stream Monitoring](#42-certificate-transparency-ct-log-stream-monitoring)
   - [4.3 Newly Registered Domains (NRDs) & Passive DNS (pDNS) Telemetry](#43-newly-registered-domains-nrds--passive-dns-pdns-telemetry)
5. [Codebase Alignment & Architecture Refactoring](#5-codebase-alignment--architecture-refactoring)
   - [5.1 Unifying Risk Fusion Feature Contract (V1 15-Feature → V2 18-Feature)](#51-unifying-risk-fusion-feature-contract-v1-15-feature--v2-18-feature)
   - [5.2 Sandbox DOM Snapshot Retention (`sandbox.html`)](#52-sandbox-dom-snapshot-retention-sandboxhtml)
   - [5.3 Chrome Extension Real-Time In-DOM Mutation Observer](#53-chrome-extension-real-time-in-dom-mutation-observer)
6. [Summary of Priority Recommendations Matrix](#6-summary-of-priority-recommendations-matrix)

---

## 1. Executive Summary

SCYTHE's current architecture (18-feature LightGBM booster, gVisor headless Chromium sandbox, MobileCLIP S0 512-dim visual embeddings, and Celery chord orchestration) places it ahead of legacy keyword/blocklist scanners.

However, cross-referencing recent research and contemporary adversary tactics reveals **critical blind spots** and high-value opportunities for evolution:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             CURRENT BLIND SPOTS SUMMARY                          │
├────────────────────────┬────────────────────────────────┬────────────────────────┤
│ Vector                 │ Current State in SCYTHE        │ Risk Exposure          │
├────────────────────────┼────────────────────────────────┼────────────────────────┤
│ Quishing (QR Codes)    │ Zero QR decoding in attachments│ 100% blind to QR lures │
│ BitB / Fake Popups     │ Static top-level URL analysis  │ Bypass via clean host  │
│ Evilginx3 / AiTM       │ Visual head matches real brand │ High false negatives   │
│ Latin Homoglyphs       │ Only checks Punycode (`xn--`)  │ Misses `rn` vs `m`     │
│ WOFF Font Ciphers      │ DOM text analysis deceived     │ Bypasses NLP filters   │
│ Captcha Shield Cloaking│ Blinded by Turnstile challenge │ Misses gated payloads  │
│ Threat Feeds           │ Isolated static inference      │ Redundant sandbox load │
│ Risk Fusion Contract   │ Hardcoded 15-feature fallback  │ Schema drift from V30  │
└────────────────────────┴────────────────────────────────┴────────────────────────┘
```

---

## 2. Threat Landscape Gaps & Evasion Defenses

### 2.1 Quishing (QR Code Phishing) in Email & Attachments
* **The Reality (2024–2025)**: Over 22% of corporate phishing lures now use QR codes embedded in PDF invoices, document attachments, or inline images (bypassing text-based Secure Email Gateways). Victims scan the code using personal mobile devices outside corporate firewall visibility.
* **Code Audit of SCYTHE**: Inspecting `containers/backend/services/email/parser/attachement_parser.py` reveals that while OLE VBA macros (`olevba`) and compressed archives (`py7zr`, `rarfile`) are parsed, there is **zero QR code extraction or image decoding**.
* **Improvement**:
  1. Add `pyzbar` and `opencv-python-headless` to `containers/backend/requirements.txt`.
  2. Integrate `extract_qr_codes()` directly into `attachement_parser.py` and `content_parser.py`:
     ```python
     import cv2
     import numpy as np
     from pyzbar import pyzbar

     def extract_qr_codes(image_bytes: bytes) -> list[str]:
         np_arr = np.frombuffer(image_bytes, np.uint8)
         img = cv2.imdecode(np_arr, cv2.IMREAD_GRAYSCALE)
         if img is None:
             return []
         decoded = pyzbar.decode(img)
         # Fallback to OpenCV QR detector if pyzbar misses styled/rounded codes
         if not decoded:
             detector = cv2.QRCodeDetector()
             data, _, _ = detector.detectAndDecode(img)
             return [data] if data else []
         return [item.data.decode("utf-8", errors="ignore") for item in decoded if item.data]
     ```
  3. When an image/PDF contains a QR code, decode the embedded payload URL and dispatch it to Tier 1 (`/api/scans/quick`) and Tier 2 sandbox automatically with metadata flag `source: "qr_code_attachment"`.

---

### 2.2 Browser-in-the-Browser (BitB) & Dynamic DOM Overlays
* **The Threat**: Attackers render simulated browser windows (complete with custom minimize/maximize buttons, a fake address bar, and fake green SSL padlocks) inside DOM overlays (`position: fixed; z-index: 999999;`) to mimic Google/Microsoft OAuth popups. Because the top-level URL belongs to a benign compromised site or an unflagged domain, URL-only models score it safe.
* **Research Reference**: KeepAware & NDSS 2024 Browser Security Studies.
* **Code Audit of SCYTHE**: `containers/backend/consistency_engine/consistency_engine.py` checks DOM elements superficially and often sets `indeterminate=True` if `sandbox.html` isn't dumped.
* **Improvement**:
  1. In the Playwright sandbox runner (`containers/sandbox/backend/runner.py`), add a BitB heuristic check: query the DOM for viewport-mimicking modal containers containing input forms whose text fields ask for credentials (`type="password"` or `autocomplete="current-password"`), but whose `window.open` origin does not match the page's actual frame context:
     ```javascript
     const detectBitB = () => {
       const modals = Array.from(document.querySelectorAll('div, iframe, section')).filter(el => {
         const style = window.getComputedStyle(el);
         return (style.position === 'fixed' || style.position === 'absolute') &&
                parseInt(style.zIndex, 10) > 1000 &&
                el.offsetWidth > 350 && el.offsetHeight > 400;
       });
       
       for (const modal of modals) {
         const hasInputs = modal.querySelectorAll('input[type="password"], input[type="email"]').length > 0;
         const hasFakeAddressBar = /https?:\/\//i.test(modal.innerText) || 
                                   modal.querySelector('[class*="address"], [class*="url"], [class*="fake-bar"]');
         if (hasInputs && hasFakeAddressBar) return true;
       }
       return false;
     };
     ```
  2. Feed `bitb_detected: bool` into the Consistency Engine as an immediate override signal.

---

### 2.3 Adversary-in-the-Middle (AiTM) / Reverse Proxy (Evilginx3, Modlishka) Detection
* **The Threat**: Reverse proxies proxy legitimate Microsoft/Google logins live, capturing credentials, session cookies, and 2FA tokens. The page HTML and visuals are **100% identical** to authentic Google/Microsoft because they are proxied in real time from the true server.
* **Research Reference**: JARM & JA4+ Active TLS Fingerprinting (Cloudflare & MITRE 2024).
* **Code Audit of SCYTHE**: If Evilginx proxies `login.microsoftonline.com`, the visual embedding will look 100% Microsoft, and the DOM forms will look legitimate. SCYTHE's `brand_in_subdomain_mismatch` catches it only if the registered domain has "microsoft" in the subdomain. If the attacker uses an arbitrary domain like `secure-auth-gateway-verify.com`, the lexical check may not score high enough.
* **Improvement**:
  1. **JARM Active Probing**: Probe target web servers with JARM. Reverse proxies running Go-based network stacks (like default Evilginx) produce distinctive JARM hashes that differ from Microsoft/Google Akamai/Front Door CDNs.
  2. **TLS Certificate SAN Mismatch**: When the Visual Head detects a Microsoft/Google logo with high confidence (>90%), but the TLS certificate issuer is Let's Encrypt / ZeroSSL instead of Microsoft/Google's corporate CA, immediately elevate risk to `HIGH`.

---

### 2.4 ASCII & Latin Zero-Day Homoglyph / Confusable Evasions
* **The Threat**: Attackers bypass Punycode checks (`has_punycode` / `xn--`) by using ASCII lookalikes that do not require internationalized domain names (IDN):
  * `rn` instead of `m` (`arnazon.com` vs `amazon.com`)
  * `vv` instead of `w` (`crovvdfense.com`)
  * `1` or `l` or `I` swapping (`paypaI.com`)
  * `cl` instead of `d` (`clocusign.com`)
* **Code Audit of SCYTHE**: In `containers/backend/services/model_features/url_features.py`, `has_punycode` only detects `xn--`. Pure ASCII lookalikes pass with `has_punycode = 0.0`.
* **Improvement**:
  1. Implement a confusable skeleton mapper using Unicode TR39 definitions:
     ```python
     CONFUSABLE_MAP = {
         "rn": "m", "vv": "w", "cl": "d", "0": "o", "1": "l",
         "v": "u", "l": "i",
     }
     def compute_homoglyph_similarity(domain: str, protected_brands: set[str]) -> float:
         normalized = domain.lower()
         for k, v in CONFUSABLE_MAP.items():
             normalized = normalized.replace(k, v)
         # Check similarity against protected brand names (e.g., Levenshtein distance)
         ...
     ```
  2. Add `homoglyph_confusable_ratio` and `target_brand_edit_distance` as Features 19 and 20 in the URL feature vector.

---

### 2.5 WOFF Font Substitution Ciphers & HTML5 Canvas Rendering
* **The Threat**: 
  * **Font Substitution**: Attackers include a custom `@font-face` `.woff` or `.woff2` file that maps scrambled ciphertext glyphs to valid English letters (e.g., the string `"x84kL"` in HTML renders visually as `"Password"`). Security parsers inspecting the DOM only see nonsense, while the victim sees a legitimate login form.
  * **HTML5 Canvas Drawing**: The login form and brand emblems are drawn directly onto an HTML5 `<canvas>` via JavaScript 2D rendering contexts rather than DOM input tags.
* **SCYTHE Defense Advantage**: SCYTHE already has an **OCR channel** (`extract_text` with Tesseract) and an independent **Visual Head**.
* **Improvement Specification**:
  * Cross-correlate OCR text against DOM text in the Consistency Engine.
  * **Heuristic**: If the OCR channel extracts sensitive keywords (`"Password"`, `"Sign in"`, `"Account"`) from the screenshot, but those keywords are **completely absent** from the raw DOM text, flag as `FONT_OBFUSCATION_SUSPECTED` or `CANVAS_RENDERING_DETECTED`.

---

### 2.6 Captcha Wall & Cloudflare Turnstile Cloaking Shields
* **The Threat**: Attackers front their phishing kits with Cloudflare Turnstile, hCaptcha, or Google reCAPTCHA v3. If an automated headless sandbox (Playwright/Chromium) visits the URL, it encounters a 403 or a captcha verification screen, never reaching the phishing payload. The scanner erroneously marks the page `SAFE`.
* **Improvement Specification**:
  1. In `containers/sandbox/backend/runner.py`, add captcha signature detection:
     ```javascript
     const detectCaptchaShield = () => {
       const hasTurnstile = !!document.querySelector('.cf-turnstile, iframe[src*="challenges.cloudflare.com"]');
       const hasRecaptcha = !!document.querySelector('.g-recaptcha, iframe[src*="google.com/recaptcha"]');
       const hasHCaptcha = !!document.querySelector('.h-captcha, iframe[src*="hcaptcha.com"]');
       return hasTurnstile || hasRecaptcha || hasHCaptcha;
     };
     ```
  2. When a captcha shield is detected, do **not** output `SAFE`. Output `SUSPICIOUS_CLOAKING_CHALLENGE` with an elevated medium-risk rating and queue for authenticated human analyst or specialized token solver.

---

## 3. Machine Learning & Model Architecture Upgrades

### 3.1 Visual Head: MobileCLIP S0 vs. Decoupled Logo Siamese (DINOv2)
* **Academic Comparison**:
  * In USENIX Security papers (*Phishpedia* and *PhishIntention*), pure whole-image embeddings often generate false positives when benign sites use similar corporate minimalist layouts (e.g., standard login portals with centered card designs).
  * Whole-image contrastive encoders (CLIP / MobileCLIP) struggle with subtle brand logo replacements and tiny 24x24 favicon or header badge impersonations.
* **Improvement**:
  * **Decoupled Logo Detection + Siamese Verification**: Use a lightweight YOLOv8-nano model trained specifically to detect identity logos within screenshots, followed by metric learning (Siamese network or DINOv2 patch similarity) against an offline catalog of top 200 impersonated brands (Microsoft, Google, PayPal, Apple, DocuSign, Binance, etc.).
  * **Why DINOv2 beats CLIP for logos**: Self-supervised DINOv2 generates dense structural patch representations that retain fine-grained typography and logo vectors, whereas CLIP prioritizes general semantic concepts.

---

### 3.2 URL Classifier: 18-Feature Contract Expansion to 28+ Features (PhiUSIIL)
* **Current State**: SCYTHE has 18 features in `url_features.py`.
* **Benchmark Reference**: The **PhiUSIIL Phishing URL Dataset** (235,795 URLs, UCI / Computers & Security 2023–2025) achieved >99.9% accuracy by adding critical structural and probabilistic signals.
* **High-Impact Features Missing in SCYTHE**:
  * `tld_risk_weight`: Statistical phishing frequency of the TLD (e.g., `.top`, `.xyz`, `.icu`, `.cfd`, `.buzz`, `.rest` vs. `.edu`, `.gov`).
  * `hex_encoded_char_count`: Counting `%20`, `%2e`, `%2f`, `%40` obfuscation tricks.
  * `char_continuation_rate`: Ratio of longest repeating alphanumeric sequence (detects DGA / random generation).
  * `tld_in_subdomain_or_path`: Attackers nesting `.com-login.top` or `legit.com/paypal.com/auth`.
  * `homoglyph_confusable_ratio`: SCYTHE currently only checks `has_punycode` (`xn--`). Attackers now use Latin lookalikes (e.g., `rn` instead of `m`, `vv` instead of `w`, `1` instead of `l`, `cl` instead of `d`) which remain raw ASCII without Punycode! Using a confusable dictionary (Unicode TR39) captures these zero-day homoglyphs.

| Feature Name | Computation Cost | Defense Benefit |
| :--- | :--- | :--- |
| `tld_risk_weight` | $<1\,\mu\text{s}$ (hash lookup) | Flags disproportionately abused TLDs (`.top`, `.xyz`, `.icu`, `.cfd`, `.buzz`). |
| `hex_encoded_char_count` | $<1\,\mu\text{s}$ (regex count) | Detects `%20`, `%2e`, `%2f`, `%40` evasion encodings. |
| `char_continuation_rate` | $3\,\mu\text{s}$ | Longest repeating character run; exposes Domain Generation Algorithms (DGA). |
| `tld_in_subdomain_or_path` | $2\,\mu\text{s}$ | Detects nested deceptive structures like `example.com-login.top` or `/paypal.com/auth`. |
| `homoglyph_confusable_ratio` | $2\,\mu\text{s}$ | Measures ratio of lookalike ASCII pairs against brand dictionaries. |

---

### 3.3 LightGBM vs. Modern Alternatives
* **Finding**: Research shows LightGBM remains the fastest CPU inference engine (2.71 µs in SCYTHE), far outperforming Neural Networks and TabNet in throughput.
* **Recommendation**: Retain LightGBM as the Tier 1 inference engine. Do not replace it with heavy Transformer/BERT models for inline URL scanning, as latency would jump from microseconds to 30–80 milliseconds, degrading Chrome Extension navigation responsiveness.
* **Tuning Opportunity**: Implement CatBoost or Monotonic Constraints in LightGBM to prevent adversarial perturbation (e.g., attackers appending long benign query strings to artificially dilute entropy scores).

---

### 3.4 Multimodal LLMs (MLLMs) & Agentic Triage (eCrime 2024 / AAAI 2025)
* **Research Reference**: *Multimodal Large Language Models for Phishing Webpage Detection* (APWG eCrime 2024) and *PhishAgent* (AAAI 2025).
* **Application in SCYTHE**:
  * Machine learning models emit probabilities, but Security Operations Center (SOC) analysts need **explainable justification** (Explainable AI / XAI) for borderline cases (verdict = `INVESTIGATE` or `MEDIUM`).
  * Implement an asynchronous Tier-3 task in Celery using a compact vision model (e.g., quantized Llama-3.2-11B-Vision or Gemini Flash) for disputed scans:
    - Input: Screenshot + extracted DOM text + URL.
    - Output: JSON explaining social engineering vectors ("Page mimics DocuSign electronic signature request with artificial urgency countdown, hosted on an unauthorized Cloudflare worker").

---

## 4. Threat Intel & OSINT Feed Ingestion

SCYTHE is currently an isolated evaluation platform. Integrating public, real-time intelligence feeds would drastically reduce sandbox compute loads:

| Threat Intel Source | Access Type | How SCYTHE Can Use It |
| :--- | :--- | :--- |
| **URLhaus (abuse.ch)** | Free REST API / daily CSV | Ingest known malware/phishing payload URLs directly into Redis Tier 0 cache (0ms lookup). |
| **OpenPhish Community Feed** | Free RSS / JSON feed | Auto-update known zero-hour phishing URLs every 15 minutes via Celery Beat. |
| **PhishTank** | Free Developer API | Second-tier consensus cross-referencing. |
| **Certificate Transparency (CT Logs)** via `certstream` | Real-time WebSocket stream | Monitor newly issued SSL certificates for target brand permutations (e.g., `*paypal*`, `*microsoft365*`). |

---

### 4.3 Newly Registered Domains (NRDs) & Passive DNS (pDNS) Telemetry
* **The Reality**: Over 82% of active phishing domains are less than 72 hours old. Established enterprise domains (Microsoft, Google, Chase) have decades of continuous registration history.
* **Implementation**:
  * In `containers/backend/services/cyberintel/domain_intel.py`, query RDAP (Registration Data Access Protocol) for `domain_age_hours`.
  * If `domain_age_hours < 72` and `brand_in_subdomain_mismatch == 1`, trigger an automated risk multiplier of $2.5\times$.

---

## 5. Codebase Alignment & Architecture Refactoring

1. **Unify Risk Fusion Contracts**:
   * In `containers/backend/risk_fusion.py`, `FEATURE_COLUMNS` is hardcoded to the 15-feature V1 contract, while `url_features.py` and v30 production models use the 18-feature V2 contract (`is_paas_subdomain`, `subdomain_entropy`, `brand_in_subdomain_mismatch`). Aligning `risk_fusion.py` to use `FEATURE_NAMES_V2` across all fallbacks avoids schema coercion friction.
2. **Persistent Sandbox DOM Dump**:
   * In `containers/backend/consistency_engine/consistency_engine.py`, `compare_dom()` defaults to `indeterminate=True` because the sandbox runner does not write an independent `sandbox.html` to disk. Updating the Playwright sandbox runner to persist `page.content()` as `sandbox.html` will enable active DOM mutation and cloaking comparison.
3. **Chrome Extension Real-Time In-DOM Mutation Observer**:
   * Currently, the extension redirects to `warning.html` upon top-level navigation. Adding a lightweight `MutationObserver` in `content.js` to inspect dynamically injected iframes or fake popup windows provides instant BitB defense directly inside the victim's tab.

---

## 6. Summary of Priority Recommendations Matrix

```
┌──────────────────┬────────────────────────────────────────────────────────┬──────────────┐
│ Priority         │ Recommended Action                                     │ Impact       │
├──────────────────┼────────────────────────────────────────────────────────┼──────────────┤
│ 🔴 High (Quick)   │ Add Quishing (QR) extraction in email attachment parser│ Closes #1 vector in email lures │
│ 🔴 High (Quick)   │ Align `risk_fusion.py` to 18-feature Contract V2       │ Eliminates legacy feature gap   │
│ 🟡 Medium         │ Add Latin homoglyph / confusable detection (ASCII)    │ Stops `rn` vs `m` lookalikes    │
│ 🟡 Medium         │ Add Captcha / Turnstile cloaking detection in sandbox  │ Stops false SAFE on gated phish │
│ 🟡 Medium         │ Ingest URLhaus & OpenPhish feeds into Redis cache     │ Saves sandbox compute costs     │
│ 🟢 Long-term     │ Add OCR vs. DOM text discrepancy (Font cipher defense)│ Defeats WOFF / canvas ciphers   │
│ 🟢 Long-term     │ Add YOLOv8-logo + Siamese / DINOv2 logo matching      │ Eliminates false positives      │
│ 🟢 Long-term     │ Asynchronous Multimodal LLM Triage for disputed scans  │ Explainable AI (XAI) for SOC    │
└──────────────────┴────────────────────────────────────────────────────────┴──────────────┘
```

```text
Phase 1: Immediate Threat Gaps (Week 1–2)
├── [High] Add pyzbar QR code extraction in attachment_parser.py
├── [High] Align risk_fusion.py FEATURE_COLUMNS to 18-feature Contract V2
└── [High] Persist sandbox.html from Playwright runner to enable DOM comparison

Phase 2: Adversary Evasion Resilience (Week 3–4)
├── [Med] Implement ASCII lookalike & confusable mapping (Unicode TR39)
├── [Med] Add BitB (Browser-in-the-Browser) DOM overlay heuristic to sandbox runner
├── [Med] Add Captcha / Turnstile challenge detection to avoid false SAFE verdicts
└── [Med] Add automated URLhaus & OpenPhish Celery Beat feed ingestion

Phase 3: SOTA Model Evolution & Explainability (Month 2)
├── [Low] Train 28-feature LightGBM model utilizing PhiUSIIL dataset features
├── [Low] Research decoupled YOLOv8-nano + DINOv2 Siamese logo verification
├── [Low] Implement OCR vs DOM discrepancy checks to catch WOFF font ciphers
└── [Low] Add Multimodal LLM reasoning for disputed / border-case investigations
```
