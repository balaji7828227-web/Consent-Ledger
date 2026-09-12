# Consent Ledger 🛡

A privacy monitoring Chrome extension built on **Manifest V3** that audits the relationship between user consent decisions and third-party tracking behavior.

> **Disclaimer & Terminology Notice**: Consent Ledger detects and flags **"Potential Violation"**, **"Suspicious Activity"**, and items that **"Require Review"**. It does not claim definitive legal guilt or guarantee GDPR/ePrivacy compliance, but rather provides an objective, cryptographic audit trail of observed browser activity.

---

## 📋 Table of Contents

- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Key Features](#key-features)
- [Architecture & Data Flow](#architecture--data-flow)
- [Project Structure](#project-structure)
- [Installation Guide](#installation-guide)
- [How to Test](#how-to-test)
- [Chrome Permission Limitations (Manifest V3)](#chrome-permission-limitations-manifest-v3)
- [Evidence Ledger & Cryptographic Integrity](#evidence-ledger--cryptographic-integrity)
- [Privacy Trust Score Model](#privacy-trust-score-model)

---

## The Problem

Under modern privacy regulations (such as GDPR, ePrivacy Directive, CCPA/CPRA), websites are legally obligated to obtain explicit, informed consent prior to deploying non-essential tracking cookies and scripts. In practice, web users routinely experience:

1. **Pre-Consent Tracking**: Analytical and advertising trackers firing immediately upon page load before the user interacts with any consent banner.
2. **Post-Rejection Tracking**: Trackers continuing to transmit telemetry and user identifiers even after the user explicitly clicks "Reject All" or "Decline".
3. **Silent Tracking**: Websites collecting behavioral data without presenting any detectable consent interface or privacy banner.

---

## The Solution

**Consent Ledger** acts as an independent client-side auditor:
- It observes DOM consent banners (CMPs) and user click decisions in real time.
- It correlates the current consent state with background network requests intercepted via `chrome.webRequest`.
- When suspicious tracking occurs contrary to the user's consent posture, Consent Ledger generates a structured, cryptographically signed (**SHA-256**) evidence record in an immutable local ledger.
- It dynamically calculates a **Privacy Trust Score** (0–100) and provides an interactive dark-mode cybersecurity dashboard.

---

## Key Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Consent Interface Detection** | Identifies Consent Management Platforms (OneTrust, Cookiebot, Didomi, Klaro, Usercentrics, Quantcast, TrustArc, and generic banners) via selector scanning and keyword heuristics (`cookie`, `consent`, `privacy`, `manage cookies`). |
| 2 | **Consent State Engine** | Tracks user consent decisions (`UNKNOWN`, `ACCEPTED`, `REJECTED`, `CUSTOM`, `NO_CONSENT_DETECTED`) through document-level capturing click listeners. |
| 3 | **Tracking Detection** | Evaluates outgoing requests against known tracking signatures (`google-analytics`, `googletagmanager`, `doubleclick`, `facebook`, `hotjar`, `mixpanel`, `segment`, `analytics`, etc.) and suspicious URL parameters (`utm_*`, `fbclid`, `gclid`, `pixel`, `/collect`). |
| 4 | **Pre-Consent Tracking Detection** | Flags tracking activity initiated while consent state is still `UNKNOWN` (`PRE_CONSENT_TRACKING`). |
| 5 | **Post-Rejection Tracking Detection** | Flags tracking activity that persists after the user explicitly rejects consent (`POST_REJECTION_TRACKING`). |
| 6 | **Silent Tracking Detection** | Flags tracking on websites that lack any detectable consent interface (`SILENT_TRACKING`). |
| 7 | **Event Timeline** | Records a timestamped audit log of all significant occurrences (`Website Opened`, `Consent Interface Detected`, `Consent Status Changed`, `Tracker Detected`, `Potential Violation Detected`). |
| 8 | **Privacy Trust Score** | Calculates a real-time score from 0 to 100 with deduction weights: `-15` (pre-consent), `-25` (post-rejection), `-20` (silent tracking), with risk thresholds: **LOW RISK** (80–100), **MODERATE RISK** (50–79), and **HIGH RISK** (0–49). |
| 9 | **Evidence Ledger** | Stores structured evidence records locally (`CL-2026-XXXXXX`) with website origin, tracker, classification, violation type, consent state, and human-readable details. |
| 10 | **SHA-256 Evidence Integrity** | Computes a SHA-256 digest of each evidence record using the standard **Web Crypto API** (`crypto.subtle.digest`) to ensure evidence immutability and verify against tampering. |

---

## Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                       Website Page                          │
│  (DOM Consent Banners, Reject/Accept Buttons, Third Parties)│
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               │                               │
               ▼                               ▼
     [ content.js ]                 [ Web Requests (HTTP/S) ]
   - Scans CMP Selectors            - Outgoing script, xhr, ping
   - Intercepts User Clicks         - Filtered by chrome.webRequest
   - Emits Consent State                       │
               │                               │
               └───────────────┬───────────────┘
                               │
                               ▼
        ┌──────────────────────────────────────────────┐
        │        background.js (Service Worker)        │
        │                                              │
        │  ┌────────────────────────────────────────┐  │
        │  │            Detection Engine            │  │
        │  │ - Evaluates: Consent State vs Request  │  │
        │  │ - Flags PRE_CONSENT_TRACKING           │  │
        │  │ - Flags POST_REJECTION_TRACKING        │  │
        │  │ - Flags SILENT_TRACKING                │  │
        │  └───────────────────┬────────────────────┘  │
        │                      │                       │
        │  ┌───────────────────▼────────────────────┐  │
        │  │      Trust Score + Web Crypto SHA-256  │  │
        │  │ - Computes Privacy Trust Score (0-100) │  │
        │  │ - Generates CL-2026-XXXXXX Record      │  │
        │  │ - Digests Canonical Payload into Hash  │  │
        │  └───────────────────┬────────────────────┘  │
        │                      │                       │
        │  ┌───────────────────▼────────────────────┐  │
        │  │      Local Persistence & Badge         │  │
        │  │ - chrome.storage.local (site_domain)   │  │
        │  │ - Action badge text & risk color       │  │
        │  └────────────────────────────────────────┘  │
        └──────────────────────┬───────────────────────┘
                               │
                               ▼
        ┌──────────────────────────────────────────────┐
        │            Popup Dashboard UI                │
        │  (popup.html / popup.css / popup.js)         │
        │  - Current Website & Privacy Trust Score     │
        │  - Risk Level & Consent Status Badge         │
        │  - Live Tracker Count & Potential Violations │
        │  - Latest Alert Card                         │
        │  - View Evidence Modal (SHA-256 Verified)    │
        │  - Event Timeline Drawer                     │
        │  - Refresh Analysis & Clear Website Data     │
        └──────────────────────────────────────────────┘
```

---

## Project Structure

```
Consent-Ledger/
│
├── extension/
│   ├── manifest.json       # Manifest V3 specification & permissions
│   ├── background.js       # Background service worker, request classifier & crypto engine
│   ├── content.js          # DOM consent scanner & capturing click listener
│   │
│   └── popup/
│       ├── popup.html      # Dark cybersecurity dashboard interface
│       ├── popup.css       # Responsive styling, cards, gauges, modals
│       └── popup.js        # Tab queries, background messaging, ledger renderer
│
└── README.md               # Complete architecture & technical documentation
```

---

## Installation Guide

1. Open Google Chrome (or Chromium-based browsers such as Brave, Edge, or Opera).
2. In the URL bar, navigate to:
   ```
   chrome://extensions
   ```
3. Enable **Developer mode** using the toggle in the upper right-hand corner.
4. Click the **Load unpacked** button.
5. Select the `extension` folder located at:
   ```
   c:\Users\balaj\OneDrive\Desktop\Consent-Ledger\extension
   ```
6. The **Consent Ledger** extension icon will appear in your Chrome toolbar. Click the puzzle icon to pin it for easy access.

---

## How to Test

### 1. Pre-Consent Tracking Test
1. Open a new tab and navigate to any news or commercial website that uses third-party analytics (e.g., a major publisher).
2. **Do not click** on the consent banner.
3. Open the **Consent Ledger** popup:
   - Notice the status: `UNKNOWN`.
   - If trackers were requested immediately on load, a `PRE_CONSENT_TRACKING` potential violation will appear.
   - The Privacy Trust Score will reflect a deduction (`-15`).

### 2. Post-Rejection Tracking Test (Core Feature)
1. On a website presenting a cookie banner with a rejection option, click **"Reject All"**, **"Reject"**, or **"Decline"**.
2. Open the **Consent Ledger** popup:
   - The Consent Status will show `REJECTED`.
   - If analytics or ad beacons fire after rejection, a `POST_REJECTION_TRACKING` alert is flagged.
   - The Privacy Trust Score will reflect a major deduction (`-25`).
   - Click **View Evidence** to inspect the evidence record with its unique `CL-2026-XXXXXX` ID and verified SHA-256 hash.

### 3. Silent Tracking Test
1. Navigate to a website that embeds third-party trackers (e.g. Google Analytics or Facebook Pixel) but presents **no consent banner**.
2. After the 4-second grace period, Consent Ledger marks the interface as `NO_CONSENT_INTERFACE_DETECTED`.
3. Observed tracking requests are flagged as `SILENT_TRACKING` (`-20` deduction).

---

## Chrome Permission Limitations (Manifest V3)

When architecting network monitoring extensions under Chrome Manifest V3, several browser-level constraints must be recognized:

### 1. `webRequest` API in MV3 is Observe-Only
- In Manifest V3, non-enterprise extensions **cannot use blocking `webRequest`** (`["blocking"]`).
- `webRequest` is strictly asynchronous and read-only. This means Consent Ledger can monitor, classify, and audit tracking requests, but cannot block or delay network packets natively without `declarativeNetRequest`.
- This is ideal for an auditing extension like Consent Ledger, as it avoids interfering with website functionality while maintaining complete visibility.

### 2. Ephemeral Background Service Workers
- Manifest V3 replaces persistent background pages with **Service Workers** that terminate after approximately 30 seconds of inactivity.
- Any in-memory JavaScript variables are destroyed when the worker goes idle.
- **Solution in Consent Ledger**: All website state, tracker lists, timeline events, and evidence records are persisted directly in `chrome.storage.local`. Tab-to-domain associations are stored in `chrome.storage.session`, ensuring zero data loss across service worker restart cycles.

### 3. Service Worker & Caching Isolation
- Subresource requests fulfilled entirely from the browser's disk cache or HTTP/3 QUIC connection pools might bypass certain `onBeforeRequest` listener cycles if `webRequest` hooks initialize after the socket handshake.
- Requests made by other extension service workers or sandboxed iframes are excluded.

### 4. DNS over HTTPS (DoH) and Encrypted SNI (ECH)
- The extension inspects application-layer URLs and HTTP hostnames passed through Chromium's network stack. It does not monitor low-level socket IP handshakes, which means domain fronting or CNAME cloaking may obscure the true destination if the tracker operates under a first-party subdomain.

### 5. Private / Incognito Mode Isolation
- By default, Chrome disables extensions in Incognito windows unless the user explicitly grants permission in `chrome://extensions` ("Allow in Incognito"). Even with permission granted, `chrome.storage.local` is isolated between standard and incognito sessions.

---

## Evidence Ledger & Cryptographic Integrity

Each evidence record adheres to the following JSON schema:

```json
{
  "evidenceId": "CL-2026-4A9F21",
  "website": "example.com",
  "tracker": "google-analytics.com",
  "classification": "KNOWN_TRACKER",
  "violationType": "POST_REJECTION_TRACKING",
  "consentState": "REJECTED",
  "timestamp": "2026-09-12T15:42:00.123Z",
  "details": "Known tracker (google-analytics.com) observed following user consent rejection. Potential non-compliance requires review.",
  "evidenceHash": "8f481c1c1f4e3cf673e4abef92067755c3c0c1cfbf27a1953d6ab2f67215f79a"
}
```

### Hash Verification
The hash is calculated over a deterministic canonical representation using the **Web Crypto API**:
```javascript
const canonicalPayload = { evidenceId, website, tracker, classification, violationType, consentState, timestamp, details };
const data = new TextEncoder().encode(JSON.stringify(canonicalPayload));
const hashBuffer = await crypto.subtle.digest('SHA-256', data);
```
When viewing evidence in the dashboard, the popup verifies the record's hash dynamically to detect any local modification.

---

## Privacy Trust Score Model

The **Privacy Trust Score** evaluates website privacy posture on a scale from `0` to `100`:

$$\text{Privacy Trust Score} = \max\Big(0, 100 - \sum \text{Deductions}\Big)$$

| Infraction | Base Deduction | Multiplier for Subsequent Occurrences |
|---|---|---|
| **Pre-Consent Tracking** | `-15` | `-5` per additional tracker |
| **Post-Rejection Tracking** | `-25` | `-5` per additional tracker |
| **Silent Tracking** | `-20` | `-5` per additional tracker |
| **Tracker Volume Penalty** | `-3` | Applied when > 3 unique third-party trackers are present |

### Risk Categorization
- **80 – 100**: 🟢 **LOW RISK** — Site exhibits minimal third-party leakage or honors consent boundaries.
- **50 – 79**: 🟡 **MODERATE RISK** — Unconfirmed or suspicious third-party activity before explicit user choices.
- **0 – 49**: 🔴 **HIGH RISK** — Persistent tracking post-rejection or significant silent tracking.
