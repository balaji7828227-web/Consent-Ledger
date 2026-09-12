/**
 * Consent Ledger - Background Service Worker (Manifest V3)
 * 
 * Analyzes the relationship between user consent and website tracking activity.
 * Operates statelessly with chrome.storage.local persistence.
 * Uses Web Crypto API for SHA-256 evidence integrity hashing.
 */

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================

// Consent Interface States
const INTERFACE_STATES = {
  DETECTED: 'CONSENT_INTERFACE_DETECTED',
  NOT_DETECTED: 'NO_CONSENT_INTERFACE_DETECTED',
  UNKNOWN: 'UNKNOWN'
};

// User Consent Decision States
const CONSENT_STATES = {
  UNKNOWN: 'UNKNOWN',
  ACCEPTED: 'ACCEPTED',
  REJECTED: 'REJECTED',
  CUSTOM: 'CUSTOM',
  NO_CONSENT_DETECTED: 'NO_CONSENT_DETECTED'
};

// Request Classifications
const REQUEST_CLASSIFICATIONS = {
  KNOWN_TRACKER: 'KNOWN_TRACKER',
  SUSPICIOUS_REQUEST: 'SUSPICIOUS_REQUEST',
  UNKNOWN_THIRD_PARTY: 'UNKNOWN_THIRD_PARTY',
  FIRST_PARTY: 'FIRST_PARTY'
};

// Violation Types (strictly non-accusatory terminology)
const VIOLATION_TYPES = {
  PRE_CONSENT_TRACKING: 'PRE_CONSENT_TRACKING',
  POST_REJECTION_TRACKING: 'POST_REJECTION_TRACKING',
  SILENT_TRACKING: 'SILENT_TRACKING'
};

// Known tracker domain patterns
const KNOWN_TRACKER_PATTERNS = [
  'google-analytics',
  'googletagmanager',
  'doubleclick',
  'facebook',
  'connect.facebook',
  'hotjar',
  'mixpanel',
  'segment',
  'analytics',
  'clarity.ms',
  'criteo',
  'amplitude',
  'scorecardresearch',
  'quantserve',
  'outbrain',
  'taboola',
  'adnxs',
  'matomo',
  'mouseflow',
  'luckyorange',
  'crazyegg',
  'yandex.ru/metrika'
];

// Suspicious tracking query parameters & path signatures
const SUSPICIOUS_PARAMS = [
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'fbclid',
  'gclid',
  'msclkid',
  'mc_eid',
  'dclid',
  'pixel_id',
  'visitor_id',
  'client_id'
];

const SUSPICIOUS_PATHS = [
  '/collect',
  '/pixel',
  '/tr/',
  '/track',
  '/telemetry',
  '/events',
  '/beacon',
  '/ping',
  '/log'
];

// Backend API configuration
const BACKEND_API_URL = 'https://consent-ledger.onrender.com/api/events';

/**
 * Sends event data to the external backend API asynchronously using fetch POST.
 * Fully error-tolerant: failures (e.g. backend offline, network error) are caught
 * and handled without impacting the extension's local analysis, storage, or execution.
 *
 * @param {Object} payload - The event data to transmit
 * @returns {Promise<boolean>} - True if successfully dispatched, false otherwise
 */
async function sendEventToBackend(payload) {
  if (!BACKEND_API_URL || !payload) return false;
  try {
    const response = await fetch(BACKEND_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      console.warn(`[Consent Ledger] Backend responded with HTTP status ${response.status}`);
      return false;
    }
    return true;
  } catch (error) {
    // Graceful error handling: ensure extension never throws or breaks if backend is offline
    console.debug('[Consent Ledger] Backend offline or unreachable:', error.message);
    return false;
  }
}

// ============================================================================
// STORAGE & SITE DATA HELPERS
// ============================================================================

/**
 * Normalizes hostnames to standard domain format.
 */
function normalizeHostname(hostname) {
  if (!hostname) return '';
  return hostname.toLowerCase().replace(/^www\./, '');
}

/**
 * Extracts the base registered domain (eTLD+1 approximation) for first-party checks.
 */
function getBaseDomain(hostname) {
  if (!hostname) return '';
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return parts.join('.');
  // Check common two-part TLDs (e.g. co.uk, com.au, org.uk)
  const secondLast = parts[parts.length - 2];
  if (['co', 'com', 'org', 'net', 'gov', 'edu'].includes(secondLast) && parts.length > 2) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Creates default site data object.
 */
function createDefaultSiteData(domain) {
  return {
    website: domain,
    firstSeen: new Date().toISOString(),
    lastUpdated: new Date().toISOString(),
    consentInterface: INTERFACE_STATES.UNKNOWN,
    consentState: CONSENT_STATES.UNKNOWN,
    trustScore: 100,
    riskLevel: 'LOW RISK',
    trackers: [],
    violations: [],
    evidenceLedger: [],
    timeline: [],
    latestAlert: null
  };
}

/**
 * Retrieves site data from chrome.storage.local.
 */
async function getSiteData(domain) {
  if (!domain) return null;
  const key = `site_${domain}`;
  try {
    const result = await chrome.storage.local.get(key);
    if (result[key]) {
      return result[key];
    }
    return createDefaultSiteData(domain);
  } catch (error) {
    console.error(`[Consent Ledger] Error loading site data for ${domain}:`, error);
    return createDefaultSiteData(domain);
  }
}

/**
 * Saves site data to chrome.storage.local.
 */
async function saveSiteData(domain, data) {
  if (!domain || !data) return;
  data.lastUpdated = new Date().toISOString();
  const key = `site_${domain}`;
  try {
    await chrome.storage.local.set({ [key]: data });
  } catch (error) {
    console.error(`[Consent Ledger] Error saving site data for ${domain}:`, error);
  }
}

/**
 * Clears stored analysis data for a given website.
 */
async function clearSiteData(domain) {
  if (!domain) return false;
  const key = `site_${domain}`;
  try {
    await chrome.storage.local.remove(key);
    return true;
  } catch (error) {
    console.error(`[Consent Ledger] Error clearing site data for ${domain}:`, error);
    return false;
  }
}

// ============================================================================
// CRYPTOGRAPHIC EVIDENCE ENGINE (SHA-256 via Web Crypto API)
// ============================================================================

/**
 * Generates an evidence ID in format CL-2026-XXXXXX.
 */
function generateEvidenceId() {
  const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let randomHex = '';
  for (let i = 0; i < 6; i++) {
    randomHex += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `CL-2026-${randomHex}`;
}

/**
 * Generates a canonical SHA-256 hash string for an evidence record.
 */
async function generateEvidenceHash(record) {
  const canonicalPayload = {
    evidenceId: record.evidenceId,
    website: record.website,
    tracker: record.tracker,
    classification: record.classification,
    violationType: record.violationType,
    consentState: record.consentState,
    timestamp: record.timestamp,
    details: record.details
  };

  const jsonString = JSON.stringify(canonicalPayload);
  const encoder = new TextEncoder();
  const data = encoder.encode(jsonString);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Verifies that an evidence record's SHA-256 hash matches its contents.
 */
async function verifyEvidenceRecord(record) {
  if (!record || !record.evidenceHash) return false;
  try {
    const calculatedHash = await generateEvidenceHash(record);
    return calculatedHash === record.evidenceHash;
  } catch (error) {
    console.error('[Consent Ledger] Verification error:', error);
    return false;
  }
}

// ============================================================================
// PRIVACY TRUST SCORE ENGINE
// ============================================================================

/**
 * Computes the Privacy Trust Score from 0 to 100 based on detected activity.
 * 
 * Rules:
 * - Starting score: 100
 * - Known tracker before consent: -15 (plus -5 for each additional pre-consent tracker)
 * - Known tracker after rejection: -25 (plus -5 for each additional post-rejection tracker)
 * - Silent tracking (tracking without consent UI): -20
 * - Multiple suspicious trackers: -5 per additional tracker
 * 
 * Risk levels:
 * - 80 - 100: LOW RISK
 * - 50 - 79: MODERATE RISK
 * - 0 - 49: HIGH RISK
 */
function calculateTrustScore(siteData) {
  let score = 100;

  const preConsentViolations = siteData.evidenceLedger.filter(
    e => e.violationType === VIOLATION_TYPES.PRE_CONSENT_TRACKING
  );
  const postRejectionViolations = siteData.evidenceLedger.filter(
    e => e.violationType === VIOLATION_TYPES.POST_REJECTION_TRACKING
  );
  const silentViolations = siteData.evidenceLedger.filter(
    e => e.violationType === VIOLATION_TYPES.SILENT_TRACKING
  );

  // Pre-consent tracking deduction
  if (preConsentViolations.length > 0) {
    score -= 15;
    if (preConsentViolations.length > 1) {
      score -= (preConsentViolations.length - 1) * 5;
    }
  }

  // Post-rejection tracking deduction (Core high-impact violation)
  if (postRejectionViolations.length > 0) {
    score -= 25;
    if (postRejectionViolations.length > 1) {
      score -= (postRejectionViolations.length - 1) * 5;
    }
  }

  // Silent tracking deduction
  if (silentViolations.length > 0) {
    score -= 20;
    if (silentViolations.length > 1) {
      score -= (silentViolations.length - 1) * 5;
    }
  }

  // Additional deduction for total tracker diversity
  const uniqueTrackers = new Set(siteData.trackers.map(t => t.domain));
  if (uniqueTrackers.size > 3) {
    score -= Math.min(20, (uniqueTrackers.size - 3) * 3);
  }

  // Clamp between 0 and 100
  score = Math.max(0, Math.min(100, Math.round(score)));

  let riskLevel = 'LOW RISK';
  if (score < 50) {
    riskLevel = 'HIGH RISK';
  } else if (score < 80) {
    riskLevel = 'MODERATE RISK';
  }

  return { score, riskLevel };
}

// ============================================================================
// TIMELINE LOGGING HELPER
// ============================================================================

/**
 * Adds an event to the site timeline (keeps up to 100 most recent events).
 */
function addTimelineEvent(siteData, eventName, details) {
  if (!siteData.timeline) {
    siteData.timeline = [];
  }

  const entry = {
    timestamp: new Date().toISOString(),
    event: eventName,
    details: details || ''
  };

  // Prevent duplicate back-to-back identical events within 1 second
  const lastEvent = siteData.timeline[siteData.timeline.length - 1];
  if (
    lastEvent &&
    lastEvent.event === entry.event &&
    lastEvent.details === entry.details
  ) {
    return;
  }

  siteData.timeline.push(entry);

  if (siteData.timeline.length > 100) {
    siteData.timeline = siteData.timeline.slice(-100);
  }
}

// ============================================================================
// BADGE UPDATE HELPER
// ============================================================================

/**
 * Updates the extension action badge for the active tab.
 */
async function updateActionBadge(tabId, siteData) {
  if (!tabId || tabId < 0 || !siteData) return;

  try {
    const violationCount = siteData.evidenceLedger ? siteData.evidenceLedger.length : 0;
    const text = violationCount > 0 ? String(violationCount) : '';
    await chrome.action.setBadgeText({ tabId, text });

    let color = '#10b981'; // Green (Low Risk)
    if (siteData.riskLevel === 'HIGH RISK' || violationCount > 0) {
      color = '#ef4444'; // Red (High Risk or Violations)
    } else if (siteData.riskLevel === 'MODERATE RISK') {
      color = '#f59e0b'; // Amber (Moderate Risk)
    }

    await chrome.action.setBadgeBackgroundColor({ tabId, color });
  } catch (error) {
    // Tab might have closed or not support action badges
  }
}

// ============================================================================
// REQUEST CLASSIFIER & TRACKING DETECTOR
// ============================================================================

/**
 * Classifies an incoming web request.
 */
function classifyRequest(requestUrl, initiatorHostname) {
  try {
    const urlObj = new URL(requestUrl);
    const requestHostname = normalizeHostname(urlObj.hostname);
    const requestPath = urlObj.pathname.toLowerCase();
    const requestSearch = urlObj.search.toLowerCase();
    const initiatorBase = getBaseDomain(initiatorHostname);
    const requestBase = getBaseDomain(requestHostname);

    // First party check: identical base domain
    if (initiatorBase && requestBase && initiatorBase === requestBase) {
      return {
        classification: REQUEST_CLASSIFICATIONS.FIRST_PARTY,
        domain: requestHostname,
        matchedPattern: null
      };
    }

    // Check Known Tracker patterns
    for (const pattern of KNOWN_TRACKER_PATTERNS) {
      if (requestHostname.includes(pattern) || requestUrl.toLowerCase().includes(pattern)) {
        return {
          classification: REQUEST_CLASSIFICATIONS.KNOWN_TRACKER,
          domain: requestHostname,
          matchedPattern: pattern
        };
      }
    }

    // Check Suspicious Request (suspicious parameters, paths, or ad terms)
    for (const param of SUSPICIOUS_PARAMS) {
      if (requestSearch.includes(`${param}=`)) {
        return {
          classification: REQUEST_CLASSIFICATIONS.SUSPICIOUS_REQUEST,
          domain: requestHostname,
          matchedPattern: param
        };
      }
    }

    for (const path of SUSPICIOUS_PATHS) {
      if (requestPath.includes(path)) {
        return {
          classification: REQUEST_CLASSIFICATIONS.SUSPICIOUS_REQUEST,
          domain: requestHostname,
          matchedPattern: path
        };
      }
    }

    // Generic unknown third party
    return {
      classification: REQUEST_CLASSIFICATIONS.UNKNOWN_THIRD_PARTY,
      domain: requestHostname,
      matchedPattern: null
    };
  } catch (error) {
    return {
      classification: REQUEST_CLASSIFICATIONS.UNKNOWN_THIRD_PARTY,
      domain: 'unknown',
      matchedPattern: null
    };
  }
}

/**
 * Processes a detected tracking request, checking for potential violations.
 */
async function processTrackingRequest(tabId, initiatorHostname, requestUrl) {
  const domain = normalizeHostname(initiatorHostname);
  if (!domain) return;

  const { classification, domain: trackerDomain, matchedPattern } = classifyRequest(requestUrl, domain);

  // We only track KNOWN_TRACKER, SUSPICIOUS_REQUEST, and relevant third parties
  if (classification === REQUEST_CLASSIFICATIONS.FIRST_PARTY) {
    return;
  }

  const siteData = await getSiteData(domain);

  // Record tracker entry
  let trackerEntry = siteData.trackers.find(t => t.domain === trackerDomain);
  const isNewTracker = !trackerEntry;
  if (!trackerEntry) {
    trackerEntry = {
      domain: trackerDomain,
      sampleUrl: requestUrl.length > 200 ? requestUrl.substring(0, 197) + '...' : requestUrl,
      classification,
      matchedPattern,
      firstDetected: new Date().toISOString(),
      requestCount: 1
    };
    siteData.trackers.push(trackerEntry);
    addTimelineEvent(
      siteData,
      'Tracker Detected',
      `Identified ${classification} from ${trackerDomain} (match: ${matchedPattern || 'third-party'})`
    );
  } else {
    trackerEntry.requestCount++;
  }

  // Send tracker detection event to backend API
  sendEventToBackend({
    eventType: 'TRACKER_DETECTED',
    website: domain,
    tracker: trackerDomain,
    classification,
    matchedPattern,
    requestUrl: requestUrl.length > 300 ? requestUrl.substring(0, 297) + '...' : requestUrl,
    consentState: siteData.consentState,
    isNewTracker,
    requestCount: trackerEntry.requestCount,
    timestamp: new Date().toISOString()
  });

  // Evaluate Potential Violations
  let violationType = null;
  let alertTitle = null;
  let violationDetails = null;

  // Feature 4: Pre-Consent Tracking
  // If Consent State = UNKNOWN AND Known Tracker detected
  if (
    siteData.consentState === CONSENT_STATES.UNKNOWN &&
    classification === REQUEST_CLASSIFICATIONS.KNOWN_TRACKER
  ) {
    violationType = VIOLATION_TYPES.PRE_CONSENT_TRACKING;
    alertTitle = 'Potential Pre-Consent Tracking';
    violationDetails = `Known tracker (${trackerDomain}) observed before explicit user consent decision was recorded. Requires review.`;
  }
  // Feature 5: Post-Rejection Tracking (Main feature)
  // If Consent State = REJECTED AND Known Tracker detected
  else if (
    siteData.consentState === CONSENT_STATES.REJECTED &&
    classification === REQUEST_CLASSIFICATIONS.KNOWN_TRACKER
  ) {
    violationType = VIOLATION_TYPES.POST_REJECTION_TRACKING;
    alertTitle = 'Potential Post-Rejection Tracking';
    violationDetails = `Known tracker (${trackerDomain}) observed following user consent rejection. Potential non-compliance requires review.`;
  }
  // Feature 6: Silent Tracking
  // If No detectable consent interface exists AND tracking activity detected
  else if (
    siteData.consentInterface === INTERFACE_STATES.NOT_DETECTED &&
    (classification === REQUEST_CLASSIFICATIONS.KNOWN_TRACKER || classification === REQUEST_CLASSIFICATIONS.SUSPICIOUS_REQUEST)
  ) {
    violationType = VIOLATION_TYPES.SILENT_TRACKING;
    alertTitle = 'Potential Silent Tracking';
    violationDetails = `Tracking activity (${trackerDomain}) observed without a detectable user consent interface. Requires review.`;
  }

  // If a violation was identified, generate evidence record with SHA-256 hash
  if (violationType) {
    // Check if we already logged this exact violation for this tracker to avoid duplicate spam
    const existingEvidence = siteData.evidenceLedger.find(
      e => e.tracker === trackerDomain && e.violationType === violationType
    );

    if (!existingEvidence) {
      const evidenceRecord = {
        evidenceId: generateEvidenceId(),
        website: domain,
        tracker: trackerDomain,
        classification,
        violationType,
        consentState: siteData.consentState,
        timestamp: new Date().toISOString(),
        details: violationDetails,
        evidenceHash: ''
      };

      // Generate SHA-256 hash using Web Crypto API
      evidenceRecord.evidenceHash = await generateEvidenceHash(evidenceRecord);

      siteData.evidenceLedger.push(evidenceRecord);
      if (!siteData.violations.includes(violationType)) {
        siteData.violations.push(violationType);
      }

      siteData.latestAlert = {
        title: alertTitle,
        type: violationType,
        tracker: trackerDomain,
        timestamp: evidenceRecord.timestamp,
        details: violationDetails
      };

      addTimelineEvent(
        siteData,
        'Potential Violation Detected',
        `${alertTitle} [${evidenceRecord.evidenceId}] - ${trackerDomain}`
      );

      // Send potential violation event to backend API
      sendEventToBackend({
        eventType: 'POTENTIAL_VIOLATION_DETECTED',
        website: domain,
        violationType,
        alertTitle,
        tracker: trackerDomain,
        classification,
        consentState: siteData.consentState,
        evidenceId: evidenceRecord.evidenceId,
        evidenceHash: evidenceRecord.evidenceHash,
        evidence: evidenceRecord,
        details: violationDetails,
        timestamp: evidenceRecord.timestamp
      });
    }
  }

  // Recalculate Trust Score
  const { score, riskLevel } = calculateTrustScore(siteData);
  siteData.trustScore = score;
  siteData.riskLevel = riskLevel;

  await saveSiteData(domain, siteData);
  await updateActionBadge(tabId, siteData);
}

// ============================================================================
// CHROME EVENT LISTENERS
// ============================================================================

/**
 * Tab to Domain mapping stored in chrome.storage.session to handle service worker wakes.
 */
async function setTabDomain(tabId, domain) {
  try {
    await chrome.storage.session.set({ [`tab_${tabId}`]: domain });
  } catch (e) {
    // chrome.storage.session might not be available in some environments
  }
}

async function getTabDomain(tabId) {
  try {
    const res = await chrome.storage.session.get([`tab_${tabId}`]);
    return res[`tab_${tabId}`] || null;
  } catch (e) {
    return null;
  }
}

/**
 * Clean up tab mappings when a tab is closed.
 */
chrome.tabs.onRemoved.addListener(async (tabId) => {
  try {
    await chrome.storage.session.remove([`tab_${tabId}`]);
  } catch (e) {}
});

/**
 * Monitor Web Requests via chrome.webRequest.onBeforeRequest.
 * Captures all third-party tracking attempts across all frame types (scripts, images, beacons, xhr).
 */
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Ignore top-level page navigations themselves
    if (details.type === 'main_frame') {
      return;
    }

    // Ignore extension internal requests, devtools, or chrome-specific URLs
    if (
      details.url.startsWith('chrome-extension://') ||
      details.url.startsWith('chrome://') ||
      details.url.startsWith('devtools://') ||
      details.url.startsWith('about:')
    ) {
      return;
    }

    (async () => {
      let initiatorDomain = '';

      if (details.initiator) {
        try {
          const initUrl = new URL(details.initiator);
          if (initUrl.protocol === 'http:' || initUrl.protocol === 'https:') {
            initiatorDomain = initUrl.hostname;
          }
        } catch (e) {}
      }

      // Fallback: look up domain from tab
      if (!initiatorDomain && details.tabId >= 0) {
        initiatorDomain = await getTabDomain(details.tabId);
        if (!initiatorDomain) {
          try {
            const tab = await chrome.tabs.get(details.tabId);
            if (tab && tab.url) {
              const parsed = new URL(tab.url);
              if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                initiatorDomain = parsed.hostname;
                await setTabDomain(details.tabId, initiatorDomain);
              }
            }
          } catch (e) {}
        }
      }

      if (initiatorDomain) {
        await processTrackingRequest(details.tabId, initiatorDomain, details.url);
      }
    })();
  },
  { urls: ['<all_urls>'] }
);

/**
 * Message Passing Listener for Content Script & Popup Dashboard.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (!message || !message.type) {
        sendResponse({ error: 'Invalid message structure' });
        return;
      }

      switch (message.type) {
        case 'PAGE_OPENED': {
          const domain = normalizeHostname(message.domain);
          if (!domain) {
            sendResponse({ status: 'ignored' });
            return;
          }

          if (sender.tab && sender.tab.id) {
            await setTabDomain(sender.tab.id, domain);
          }

          const siteData = await getSiteData(domain);
          addTimelineEvent(
            siteData,
            'Website Opened',
            `Loaded ${domain} (${message.url || 'URL'})`
          );

          await saveSiteData(domain, siteData);
          if (sender.tab && sender.tab.id) {
            await updateActionBadge(sender.tab.id, siteData);
          }

          sendResponse({ status: 'ok', siteData });
          break;
        }

        case 'CONSENT_INTERFACE_STATUS': {
          const domain = normalizeHostname(message.domain);
          if (!domain) {
            sendResponse({ status: 'ignored' });
            return;
          }

          const siteData = await getSiteData(domain);
          const oldInterface = siteData.consentInterface;
          siteData.consentInterface = message.status;

          if (message.status === INTERFACE_STATES.DETECTED) {
            addTimelineEvent(
              siteData,
              'Consent Interface Detected',
              `Identified consent banner or CMP (${message.details || 'Standard UI'})`
            );
          } else if (message.status === INTERFACE_STATES.NOT_DETECTED) {
            addTimelineEvent(
              siteData,
              'No Consent Interface Detected',
              'No cookie banner or consent management platform was found after DOM inspection.'
            );

            // If tracking already occurred and no interface is detected, trigger SILENT_TRACKING
            if (siteData.trackers.length > 0) {
              for (const tracker of siteData.trackers) {
                if (
                  tracker.classification === REQUEST_CLASSIFICATIONS.KNOWN_TRACKER ||
                  tracker.classification === REQUEST_CLASSIFICATIONS.SUSPICIOUS_REQUEST
                ) {
                  const alreadyLogged = siteData.evidenceLedger.find(
                    e => e.tracker === tracker.domain && e.violationType === VIOLATION_TYPES.SILENT_TRACKING
                  );

                  if (!alreadyLogged) {
                    const evidenceRecord = {
                      evidenceId: generateEvidenceId(),
                      website: domain,
                      tracker: tracker.domain,
                      classification: tracker.classification,
                      violationType: VIOLATION_TYPES.SILENT_TRACKING,
                      consentState: siteData.consentState,
                      timestamp: new Date().toISOString(),
                      details: `Tracking activity (${tracker.domain}) observed without a detectable consent interface. Requires review.`,
                      evidenceHash: ''
                    };
                    evidenceRecord.evidenceHash = await generateEvidenceHash(evidenceRecord);

                    siteData.evidenceLedger.push(evidenceRecord);
                    if (!siteData.violations.includes(VIOLATION_TYPES.SILENT_TRACKING)) {
                      siteData.violations.push(VIOLATION_TYPES.SILENT_TRACKING);
                    }

                    siteData.latestAlert = {
                      title: 'Potential Silent Tracking',
                      type: VIOLATION_TYPES.SILENT_TRACKING,
                      tracker: tracker.domain,
                      timestamp: evidenceRecord.timestamp,
                      details: evidenceRecord.details
                    };

                    addTimelineEvent(
                      siteData,
                      'Potential Violation Detected',
                      `Potential Silent Tracking [${evidenceRecord.evidenceId}] - ${tracker.domain}`
                    );

                    // Send potential violation event to backend API
                    sendEventToBackend({
                      eventType: 'POTENTIAL_VIOLATION_DETECTED',
                      website: domain,
                      violationType: VIOLATION_TYPES.SILENT_TRACKING,
                      alertTitle: 'Potential Silent Tracking',
                      tracker: tracker.domain,
                      classification: tracker.classification,
                      consentState: siteData.consentState,
                      evidenceId: evidenceRecord.evidenceId,
                      evidenceHash: evidenceRecord.evidenceHash,
                      evidence: evidenceRecord,
                      details: evidenceRecord.details,
                      timestamp: evidenceRecord.timestamp
                    });
                  }
                }
              }
            }
          }

          const { score, riskLevel } = calculateTrustScore(siteData);
          siteData.trustScore = score;
          siteData.riskLevel = riskLevel;

          await saveSiteData(domain, siteData);
          if (sender.tab && sender.tab.id) {
            await updateActionBadge(sender.tab.id, siteData);
          }

          sendResponse({ status: 'ok', siteData });
          break;
        }

        case 'CONSENT_STATE_CHANGED': {
          const domain = normalizeHostname(message.domain);
          if (!domain) {
            sendResponse({ status: 'ignored' });
            return;
          }

          const siteData = await getSiteData(domain);
          const previousState = siteData.consentState;
          siteData.consentState = message.newState;

          addTimelineEvent(
            siteData,
            'Consent Status Changed',
            `User action: "${message.buttonText || 'Direct action'}". Consent state transitioned from ${previousState} to ${message.newState}.`
          );

          // If transition is to REJECTED, immediately verify if known trackers were already active or requested
          if (message.newState === CONSENT_STATES.REJECTED) {
            for (const tracker of siteData.trackers) {
              if (tracker.classification === REQUEST_CLASSIFICATIONS.KNOWN_TRACKER) {
                const alreadyLogged = siteData.evidenceLedger.find(
                  e => e.tracker === tracker.domain && e.violationType === VIOLATION_TYPES.POST_REJECTION_TRACKING
                );

                if (!alreadyLogged) {
                  const evidenceRecord = {
                    evidenceId: generateEvidenceId(),
                    website: domain,
                    tracker: tracker.domain,
                    classification: tracker.classification,
                    violationType: VIOLATION_TYPES.POST_REJECTION_TRACKING,
                    consentState: CONSENT_STATES.REJECTED,
                    timestamp: new Date().toISOString(),
                    details: `Known tracker (${tracker.domain}) observed following user consent rejection. Potential non-compliance requires review.`,
                    evidenceHash: ''
                  };
                  evidenceRecord.evidenceHash = await generateEvidenceHash(evidenceRecord);

                  siteData.evidenceLedger.push(evidenceRecord);
                  if (!siteData.violations.includes(VIOLATION_TYPES.POST_REJECTION_TRACKING)) {
                    siteData.violations.push(VIOLATION_TYPES.POST_REJECTION_TRACKING);
                  }

                  siteData.latestAlert = {
                    title: 'Potential Post-Rejection Tracking',
                    type: VIOLATION_TYPES.POST_REJECTION_TRACKING,
                    tracker: tracker.domain,
                    timestamp: evidenceRecord.timestamp,
                    details: evidenceRecord.details
                  };

                  addTimelineEvent(
                    siteData,
                    'Potential Violation Detected',
                    `Potential Post-Rejection Tracking [${evidenceRecord.evidenceId}] - ${tracker.domain}`
                  );

                  // Send potential violation event to backend API
                  sendEventToBackend({
                    eventType: 'POTENTIAL_VIOLATION_DETECTED',
                    website: domain,
                    violationType: VIOLATION_TYPES.POST_REJECTION_TRACKING,
                    alertTitle: 'Potential Post-Rejection Tracking',
                    tracker: tracker.domain,
                    classification: tracker.classification,
                    consentState: CONSENT_STATES.REJECTED,
                    evidenceId: evidenceRecord.evidenceId,
                    evidenceHash: evidenceRecord.evidenceHash,
                    evidence: evidenceRecord,
                    details: evidenceRecord.details,
                    timestamp: evidenceRecord.timestamp
                  });
                }
              }
            }
          }

          const { score, riskLevel } = calculateTrustScore(siteData);
          siteData.trustScore = score;
          siteData.riskLevel = riskLevel;

          await saveSiteData(domain, siteData);
          if (sender.tab && sender.tab.id) {
            await updateActionBadge(sender.tab.id, siteData);
          }

          sendResponse({ status: 'ok', siteData });
          break;
        }

        case 'GET_SITE_DATA': {
          const domain = normalizeHostname(message.domain);
          const siteData = await getSiteData(domain);
          sendResponse({ siteData });
          break;
        }

        case 'CLEAR_SITE_DATA': {
          const domain = normalizeHostname(message.domain);
          const cleared = await clearSiteData(domain);
          const freshData = createDefaultSiteData(domain);
          if (message.tabId) {
            await updateActionBadge(message.tabId, freshData);
          }
          sendResponse({ success: cleared, siteData: freshData });
          break;
        }

        case 'VERIFY_EVIDENCE': {
          const isValid = await verifyEvidenceRecord(message.record);
          sendResponse({ isValid });
          break;
        }

        default:
          sendResponse({ error: 'Unknown message type' });
      }
    } catch (err) {
      console.error('[Consent Ledger] onMessage error:', err);
      sendResponse({ error: err.message });
    }
  })();

  return true; // Keeps async message response port open
});
