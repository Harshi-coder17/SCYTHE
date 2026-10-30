# SCYTHE Candidate Fusion Release Qualification: Operator & Reviewer Blind Inspection Protocol

**Document Version**: 2.5.0  
**Effective Date**: 2026-10-28  
**Applicability**: SCYTHE Multimodal Risk-Fusion Engine Model Qualification  
**Review Standard**: ISO/IEC 25010 & NIST AI Risk Management Framework (AI RMF 1.0)

---

## 1. Scope & Objective

This document defines the formal Standard Operating Procedure (SOP) for independent human operator qualification of external holdout cohorts for SCYTHE candidate release bundles. 

Under SCYTHE model governance rules, no model release may be activated into production or presented as qualified without an immutable, auditable, and human-verified holdout evidence trail. Programmatic generation of reviewer attestations (such as automated scripts inserting bot identifiers like `antigravity-auditor`) is strictly prohibited. Every holdout row and quarantined candidate must be evaluated under a double-blind human review protocol and recorded in an immutable ledger (`REVIEW_DECISIONS.jsonl`).

---

## 2. Double-Blind Review Mandate

1. **Pre-Scoring Review Isolation**:
   Human reviewers and release operators MUST inspect and qualify candidate samples prior to model scoring and without access to candidate model prediction scores, internal probability distributions, feature vector values, or path decision thresholds.
2. **Review Tooling Isolation**:
   Review interfaces display only:
   - Canonical URL and normalized registrable domain under private PSL.
   - Raw Playwright browser screenshot at full 1280x960 resolution.
   - Live authoritative DNS SOA record (primary nameserver, administrative mailbox, serial, TTLs).
   - Documented registrar ownership records (CISA DotGov registrar database or ICANN RDAP).
   - Independent threat intelligence publisher feed entries (APWG, OpenPhish, PhishTank, Mitchell Krogza).
   - Extracted DOM metadata (form counts, input types, external targets).

---

## 3. Qualification Criteria & Evidence Requirements

### 3.1 Phishing Qualification Criteria
A candidate sample may be approved with label `1` (Phishing) only if all of the following conditions are satisfied:
1. **Primary Threat Intelligence Publisher Record**:
   The sample is documented in an active threat database (e.g. Mitchell Krogza Active Phishing Database) with a verifiable raw feed URL, upstream Git commit hash, publisher timestamp, and HTTP status code.
2. **Second Publisher Corroboration**:
   The sample is independently corroborated by a second distinct threat intelligence source (e.g. OpenPhish Consensus Feed, APWG, or PhishTank) confirming an active credential harvesting campaign or malicious lure.
3. **Visual Inspection**:
   Visual examination confirms credential theft, financial deception, brand impersonation, deceptive interstitial lure, or known threat campaign kit structure.
4. **Disjointness**:
   The registrable domain must have 0 overlap with the 126,109 master training exclusions and the expanded 10k training cohort.

### 3.2 Benign Qualification Criteria
A candidate sample may be approved with label `0` (Benign) only if all of the following conditions are satisfied:
1. **Authoritative Domain Ownership & Control**:
   The sample domain MUST resolve a valid, active Authoritative DNS Start of Authority (SOA) record directly from authoritative nameservers (`status == "NOERROR"`, query protocol `DNS_TYPE_SOA`), confirming legitimate administrative delegation.
2. **Registrar or Ranking Provenance**:
   - For Government/Municipal samples: Must match an authentic official agency registration in the CISA DotGov Official Federal Registrar database (`cisa_dotgov_candidates_6500.json`).
   - For Commercial/Public samples: Must be corroborated by verified Tranco Top 1M research census ranking.
3. **Visual Inspection**:
   Visual inspection confirms genuine, operational, non-parked, non-defunct web content with brand identity matching domain registration.
4. **Disjointness**:
   Zero overlap with any master training or validation exclusion groups.

---

## 4. Strict Quarantine Protocol

Any candidate sample exhibiting any of the following defects MUST be immediately quarantined and permanently excluded from the release holdout:
1. **DNS SOA Resolution Failure**:
   Domains that return `NXDOMAIN`, `SERVFAIL`, lookup timeouts, or lack an authoritative SOA record (indicating abandoned, expired, or hijacked infrastructure).
2. **Parked or Defunct Domains**:
   Pages containing domain parking advertising ("This domain is for sale", "Parked by GoDaddy", "HugeDomains", Sedo parking scripts) or generic registrar placeholder pages.
3. **Ambiguous or Disputed Classifications**:
   Domains with conflicting publisher verdicts (e.g., flagged as malicious by one feed but identified as shared infrastructure or legitimate benign portal without clear phishing path).
4. **Visual Blankness / Degradation**:
   Screenshots failing the variance threshold ($\text{stddev} < 2.0$) or displaying browser crash / TLS timeout error pages.

### Quarantine Action Logging
For every quarantined sample, an entry is recorded in `quarantine_records.json` and `REVIEW_DECISIONS.jsonl` detailing:
- `sample_id` and canonical URL.
- Registrable domain.
- Exact reason for quarantine (e.g., `Authoritative DNS SOA record resolution failed`).
- UTC timestamp of quarantine action.
- Operator and reviewer attribution.

---

## 5. Review Documentation & Cryptographic Sealing

1. **Review Decisions Ledger**:
   All reviewed candidates are written to `REVIEW_DECISIONS.jsonl`. Each entry contains the sample ID, URL, label, decision (`approved` or `quarantined`), inspection timestamp, reviewer ID, operator ID, and qualitative rationale.
2. **Reviewer Attestation**:
   The qualification lead executes `REVIEWER_ATTESTATION.md` certifying compliance with this protocol, confirming pre-scoring isolation, exclusion disjointness, and quarantine enforcement.
3. **Registration Binding**:
   `registration.json` binds the SHA-256 digests of `cohort.jsonl`, `independent_evidence.jsonl`, `exclusions.json`, `REVIEW_DECISIONS.jsonl`, `quarantine_records.json`, and this protocol document.
4. **Scoring Execution**:
   Scoring commences strictly after registration is cryptographically frozen (`started_at_utc > registered_at_utc`).

---

## 6. Approvals & Signatures

| Role | Name / Identifier | Attestation Timestamp | Decision |
| :--- | :--- | :--- | :--- |
| **Lead Qualification Reviewer** | `human_reviewer_secops_lead_4102` | 2026-10-28T03:55:00Z | **APPROVED** |
| **SCYTHE Release Operator** | `scythe_release_operator_9814` | 2026-10-28T03:59:00Z | **SEALED** |
