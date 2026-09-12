# Chrome Web Store Listing — Consent Ledger

> Last Updated: 2026-09-12

## Store Listing

**Extension Name**
Consent Ledger

**Short Description**
Privacy monitor auditing the relationship between user consent and website tracking activity with SHA-256 evidence integrity.

**Detailed Description**
Consent Ledger is an independent privacy monitoring extension that analyzes how websites respect user consent choices in real time.

When browsing the web, tracking scripts frequently execute before consent is given, continue after rejection, or fire silently without any detectable consent interface. Consent Ledger detects these discrepancies, flags potential privacy violations, and generates a tamper-evident cryptographic evidence ledger.

Key Features:
- Consent Interface Detection: Identifies standard consent banners (OneTrust, Cookiebot, Didomi, Klaro, Usercentrics, TrustArc, and generic banners) using selector heuristics.
- Consent State Tracking: Captures user click actions (Accept, Reject, Manage Preferences) in real time.
- Pre-Consent Tracking Detection: Flags third-party analytics and tracking scripts firing prior to user consent.
- Post-Rejection Tracking Detection: Audits tracking activity that continues after an explicit rejection of consent.
- Silent Tracking Detection: Detects tracking behavior on websites with no visible consent banner.
- Privacy Trust Score: Dynamic 0–100 rating reflecting privacy risk (Low, Moderate, High).
- Event Timeline: Chronological record of user interactions and network tracking events.
- Evidence Ledger: Generates unique incident records (CL-2026-XXXXXX) with SHA-256 Web Crypto verification to ensure record integrity.

How to Use:
1. Pin the extension to your Chrome toolbar.
2. Browse any website.
3. Open the Consent Ledger popup to inspect the Privacy Trust Score, detected trackers, and active consent state.
4. Interact with the website's cookie banner (Accept or Reject) and watch the audit trail update live.
5. Click "View Evidence" to review cryptographically hashed incident records.

Privacy & Data Notice:
Consent Ledger operates 100% locally on your device. It does NOT send any browsing history, logs, or analytics to external servers. All data is saved exclusively inside your browser's local extension storage.

**Category**
Developer Tools / Productivity

**Single Purpose**
Audits the relationship between user cookie consent choices and third-party tracking activity on visited websites.

**Primary Language**
English

---

## Permissions Justification

| Permission | Type | Justification |
|---|---|---|
| `storage` | permissions | Required to store audit session history, tracker lists, timeline events, and SHA-256 evidence records locally in `chrome.storage.local`. |
| `tabs` | permissions | Required to identify the active tab's URL and domain name to associate network tracking requests with the correct website session. |
| `activeTab` | permissions | Required to query the active tab when opening the extension popup dashboard. |
| `webRequest` | permissions | Required to monitor outgoing third-party network requests in read-only observation mode to classify tracking domains. |
| `<all_urls>` | host_permissions | Required to monitor third-party tracking requests and detect consent interfaces across all visited websites. |

---

## Privacy & Data Use

### Data Collection
- **Does the extension collect user data?** No.
- **Does the extension transmit data off-device?** No. All analysis, evidence generation, and SHA-256 hashing occur locally in the browser runtime.

### Certification
- I certify that this extension complies with the Developer Program Policies.
- The extension does not sell user data to third parties.
- The extension does not use or transfer user data for purposes unrelated to the item's core functionality.
- The extension does not use or transfer user data for creditworthiness or lending purposes.

---

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.0.0 | 2026-09-12 | Initial release featuring Manifest V3 compliance, Consent Interface Detection, Post-Rejection Tracking Auditing, Web Crypto SHA-256 Evidence Ledger, and Privacy Trust Score. |
