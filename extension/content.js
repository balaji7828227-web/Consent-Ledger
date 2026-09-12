/**
 * Consent Ledger - Content Script
 * 
 * Injected into web pages to detect cookie/consent banners, identify interactive
 * consent buttons, and observe user consent decisions.
 */

(function () {
  'use strict';

  // Only run in top-level window for http/https URLs
  if (window.location.protocol !== 'http:' && window.location.protocol !== 'https:') {
    return;
  }

  const hostname = window.location.hostname.toLowerCase().replace(/^www\./, '');
  if (!hostname) return;

  // States
  const INTERFACE_STATES = {
    DETECTED: 'CONSENT_INTERFACE_DETECTED',
    NOT_DETECTED: 'NO_CONSENT_INTERFACE_DETECTED',
    UNKNOWN: 'UNKNOWN'
  };

  const CONSENT_STATES = {
    UNKNOWN: 'UNKNOWN',
    ACCEPTED: 'ACCEPTED',
    REJECTED: 'REJECTED',
    CUSTOM: 'CUSTOM',
    NO_CONSENT_DETECTED: 'NO_CONSENT_DETECTED'
  };

  let interfaceDetected = false;
  let observer = null;
  let fallbackTimer = null;

  // ==========================================================================
  // SAFE RUNTIME MESSAGING
  // ==========================================================================

  function sendRuntimeMessage(message) {
    if (!chrome.runtime?.id) return;
    try {
      chrome.runtime.sendMessage(message, () => {
        if (chrome.runtime.lastError) {
          // Extension might have reloaded or context invalidated
        }
      });
    } catch (e) {
      // Ignore context invalidated errors
    }
  }

  // Notify background service worker of page load
  sendRuntimeMessage({
    type: 'PAGE_OPENED',
    domain: hostname,
    url: window.location.href
  });

  // ==========================================================================
  // CMP & CONSENT INTERFACE SELECTORS & PATTERNS
  // ==========================================================================

  const KNOWN_CMP_SELECTORS = [
    // OneTrust
    '#onetrust-banner-sdk',
    '#onetrust-consent-sdk',
    '.onetrust-pc-dark-filter',
    // Cookiebot
    '#CookiebotWidget',
    '#CybotCookiebotDialog',
    // Didomi
    '#didomi-host',
    '#didomi-notice',
    // Quantcast
    '#cmp-container',
    '.qc-cmp-ui-container',
    // Klaro
    '.klaro',
    '.cookie-notice',
    // Usercentrics
    '#usercentrics-root',
    'div[data-testid="uc-default-wall"]',
    // TrustArc
    '#truste-consent-track',
    '.truste_box_overlay',
    // Civic UK
    '#ccc',
    '#ccc-module',
    // Complianz
    '.cmplz-cookiebanner',
    // Borlabs
    '.borlabs-cookie-preference',
    // Generic banner IDs & Classes
    '[id*="cookie-banner" i]',
    '[id*="cookie-notice" i]',
    '[id*="consent-banner" i]',
    '[id*="gdpr-banner" i]',
    '[class*="cookie-banner" i]',
    '[class*="cookie-notice" i]',
    '[class*="consent-banner" i]',
    '[class*="gdpr-banner" i]',
    '[aria-label*="cookie consent" i]',
    '[aria-label*="cookie preferences" i]'
  ];

  const CONSENT_KEYWORDS = [
    'cookie',
    'consent',
    'privacy',
    'accept',
    'reject',
    'preferences',
    'manage cookies',
    'tracking technologies'
  ];

  // ==========================================================================
  // INTERFACE DETECTION LOGIC
  // ==========================================================================

  /**
   * Scans the DOM for standard CMP widgets or dialog banners containing consent keywords.
   */
  function detectConsentInterface() {
    if (interfaceDetected) return true;

    // 1. Check known CMP selectors
    for (const selector of KNOWN_CMP_SELECTORS) {
      try {
        const el = document.querySelector(selector);
        if (el && el.offsetHeight > 0 && el.offsetWidth > 0) {
          interfaceDetected = true;
          sendRuntimeMessage({
            type: 'CONSENT_INTERFACE_STATUS',
            domain: hostname,
            status: INTERFACE_STATES.DETECTED,
            details: `Known selector matched: ${selector}`
          });
          cleanupDetection();
          return true;
        }
      } catch (e) {}
    }

    // 2. Check modal / dialog elements with keywords
    const candidates = document.querySelectorAll(
      '[role="dialog"], [role="alertdialog"], [aria-modal="true"], div[class*="banner" i], div[class*="modal" i], div[class*="popup" i], div[id*="banner" i]'
    );

    for (const candidate of candidates) {
      const text = (candidate.innerText || '').toLowerCase();
      if (text.length > 20 && text.length < 3000) {
        let matchCount = 0;
        for (const kw of CONSENT_KEYWORDS) {
          if (text.includes(kw)) matchCount++;
        }

        // If it contains at least 2 consent keywords (e.g. cookie + accept) and is visible
        if (matchCount >= 2 && candidate.offsetHeight > 0) {
          interfaceDetected = true;
          sendRuntimeMessage({
            type: 'CONSENT_INTERFACE_STATUS',
            domain: hostname,
            status: INTERFACE_STATES.DETECTED,
            details: `Keyword heuristic match on ${candidate.tagName.toLowerCase()}`
          });
          cleanupDetection();
          return true;
        }
      }
    }

    return false;
  }

  function cleanupDetection() {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    if (fallbackTimer) {
      clearTimeout(fallbackTimer);
      fallbackTimer = null;
    }
  }

  // Initial detection pass
  if (!detectConsentInterface()) {
    // Observe DOM mutations for asynchronously loaded CMP banners
    observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          if (detectConsentInterface()) break;
        }
      }
    });

    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true
    });

    // Grace period fallback: if after 4 seconds no banner appeared, declare NO_CONSENT_INTERFACE_DETECTED
    fallbackTimer = setTimeout(() => {
      if (!interfaceDetected) {
        cleanupDetection();
        sendRuntimeMessage({
          type: 'CONSENT_INTERFACE_STATUS',
          domain: hostname,
          status: INTERFACE_STATES.NOT_DETECTED,
          details: 'No consent banner or CMP detected within grace period'
        });
      }
    }, 4000);
  }

  // ==========================================================================
  // BUTTON DETECTION & CLICK MONITORING (CONSENT STATE ENGINE)
  // ==========================================================================

  // Regular expression patterns for consent button actions
  const ACCEPT_PATTERNS = [
    /\baccept\s+all\b/i,
    /\baccept\s+all\s+cookies\b/i,
    /\ballow\s+all\b/i,
    /\ballow\s+all\s+cookies\b/i,
    /\bi\s+accept\b/i,
    /\bi\s+agree\b/i,
    /\bagree\s+&\s+proceed\b/i,
    /\bagree\s+and\s+continue\b/i,
    /\benable\s+all\b/i,
    /^accept$/i,
    /^allow$/i,
    /^agree$/i,
    /^got\s+it$/i,
    /^ok$/i
  ];

  const REJECT_PATTERNS = [
    /\breject\s+all\b/i,
    /\breject\s+all\s+cookies\b/i,
    /\bdecline\s+all\b/i,
    /\bdisallow\s+all\b/i,
    /\bdeny\s+all\b/i,
    /\breject\s+non-essential\b/i,
    /\brefuse\s+all\b/i,
    /\bi\s+decline\b/i,
    /\bi\s+reject\b/i,
    /^reject$/i,
    /^decline$/i,
    /^disagree$/i,
    /^deny$/i,
    /^refuse$/i
  ];

  const CUSTOM_PATTERNS = [
    /\bmanage\s+preferences\b/i,
    /\bcookie\s+settings\b/i,
    /\bcookie\s+preferences\b/i,
    /\bmanage\s+cookies\b/i,
    /\bcustomize\s+settings\b/i,
    /\bcustomize\s+cookies\b/i,
    /\bmore\s+options\b/i,
    /^preferences$/i,
    /^settings$/i,
    /^customize$/i
  ];

  /**
   * Matches button text or attribute values against consent regexes.
   */
  function matchButtonPattern(text) {
    const trimmed = (text || '').trim();
    if (!trimmed || trimmed.length > 60) return null;

    for (const pattern of REJECT_PATTERNS) {
      if (pattern.test(trimmed)) return CONSENT_STATES.REJECTED;
    }
    for (const pattern of ACCEPT_PATTERNS) {
      if (pattern.test(trimmed)) return CONSENT_STATES.ACCEPTED;
    }
    for (const pattern of CUSTOM_PATTERNS) {
      if (pattern.test(trimmed)) return CONSENT_STATES.CUSTOM;
    }

    return null;
  }

  /**
   * Captures user clicks on document in capture phase to reliably detect consent decisions.
   */
  document.addEventListener(
    'click',
    (event) => {
      try {
        const target = event.target;
        if (!target) return;

        // Traverse up to find interactive button or anchor
        const interactiveEl = target.closest(
          'button, a, input[type="button"], input[type="submit"], [role="button"], .btn'
        );

        const elToInspect = interactiveEl || target;

        // Check innerText, value, aria-label, title, or id
        const textSources = [
          elToInspect.innerText,
          elToInspect.getAttribute('value'),
          elToInspect.getAttribute('aria-label'),
          elToInspect.getAttribute('title'),
          elToInspect.id,
          elToInspect.className
        ].filter(Boolean);

        for (const text of textSources) {
          const matchedDecision = matchButtonPattern(text);
          if (matchedDecision) {
            // Also store locally in chrome.storage
            try {
              chrome.storage.local.set({
                [`consent_state_${hostname}`]: {
                  state: matchedDecision,
                  timestamp: new Date().toISOString()
                }
              });
            } catch (e) {}

            // Send notification to background service worker
            sendRuntimeMessage({
              type: 'CONSENT_STATE_CHANGED',
              domain: hostname,
              newState: matchedDecision,
              buttonText: (elToInspect.innerText || elToInspect.getAttribute('value') || text).trim().substring(0, 40)
            });

            break;
          }
        }
      } catch (err) {
        console.error('[Consent Ledger Content Script] Click processing error:', err);
      }
    },
    true // Capture phase to intercept before stopPropagation
  );
})();
