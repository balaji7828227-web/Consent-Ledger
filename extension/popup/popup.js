/**
 * Consent Ledger - Popup Dashboard Script
 * 
 * Interacts with background service worker and chrome.storage to display
 * the active website's Privacy Trust Score, Consent Status, Tracker Activity,
 * Latest Alerts, and Cryptographically Hashed Evidence Ledger.
 */

(function () {
  'use strict';

  // DOM Elements
  const elWebsite = document.getElementById('currentWebsite');
  const elTrustScore = document.getElementById('trustScoreValue');
  const elScoreMeterFill = document.getElementById('scoreMeterFill');
  const elRiskLevelBadge = document.getElementById('riskLevelBadge');
  const elConsentStatusBadge = document.getElementById('consentStatusBadge');
  const elInterfaceStateText = document.getElementById('interfaceStateText');
  const elTrackersCount = document.getElementById('trackersCount');
  const elViolationsCount = document.getElementById('violationsCount');
  const elLatestAlertStatus = document.getElementById('latestAlertStatus');
  const elLatestAlertType = document.getElementById('latestAlertType');
  const elLatestAlertTracker = document.getElementById('latestAlertTracker');
  const elLatestAlertDetails = document.getElementById('latestAlertDetails');
  const elAlertCard = document.querySelector('.alert-card');

  // Buttons & Modals
  const btnViewEvidence = document.getElementById('btnViewEvidence');
  const btnViewTimeline = document.getElementById('btnViewTimeline');
  const btnRefresh = document.getElementById('btnRefresh');
  const btnClearData = document.getElementById('btnClearData');

  const evidenceModal = document.getElementById('evidenceModal');
  const timelineModal = document.getElementById('timelineModal');
  const btnCloseEvidence = document.getElementById('btnCloseEvidence');
  const btnCloseTimeline = document.getElementById('btnCloseTimeline');
  const elEvidenceList = document.getElementById('evidenceList');
  const elTimelineList = document.getElementById('timelineList');
  const elToast = document.getElementById('statusToast');

  let activeDomain = '';
  let activeTabId = null;
  let currentSiteData = null;

  // ==========================================================================
  // INITIALIZATION
  // ==========================================================================

  document.addEventListener('DOMContentLoaded', async () => {
    setupEventListeners();
    await loadActiveTabAndData();
  });

  function setupEventListeners() {
    btnRefresh.addEventListener('click', async () => {
      await loadActiveTabAndData();
      showToast('Analysis Refreshed');
    });

    btnClearData.addEventListener('click', async () => {
      if (!activeDomain) return;
      try {
        const res = await chrome.runtime.sendMessage({
          type: 'CLEAR_SITE_DATA',
          domain: activeDomain,
          tabId: activeTabId
        });
        if (res && res.siteData) {
          currentSiteData = res.siteData;
          renderDashboard(currentSiteData);
          showToast('Website data cleared');
        }
      } catch (err) {
        console.error('Failed to clear data:', err);
      }
    });

    btnViewEvidence.addEventListener('click', () => {
      renderEvidenceModal();
      evidenceModal.classList.remove('hidden');
    });

    btnCloseEvidence.addEventListener('click', () => {
      evidenceModal.classList.add('hidden');
    });

    btnViewTimeline.addEventListener('click', () => {
      renderTimelineModal();
      timelineModal.classList.remove('hidden');
    });

    btnCloseTimeline.addEventListener('click', () => {
      timelineModal.classList.add('hidden');
    });

    // Close modals on overlay backdrop click
    evidenceModal.addEventListener('click', (e) => {
      if (e.target === evidenceModal) evidenceModal.classList.add('hidden');
    });
    timelineModal.addEventListener('click', (e) => {
      if (e.target === timelineModal) timelineModal.classList.add('hidden');
    });
  }

  // ==========================================================================
  // DATA FETCHING & RENDERING
  // ==========================================================================

  async function loadActiveTabAndData() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (!tab || !tab.url) {
        renderNoWebpageState();
        return;
      }

      activeTabId = tab.id;

      let parsedUrl;
      try {
        parsedUrl = new URL(tab.url);
      } catch (e) {
        renderNoWebpageState();
        return;
      }

      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        renderNoWebpageState(parsedUrl.protocol);
        return;
      }

      activeDomain = parsedUrl.hostname.toLowerCase().replace(/^www\./, '');
      elWebsite.textContent = activeDomain;

      // Query Background Worker for site analysis
      const response = await chrome.runtime.sendMessage({
        type: 'GET_SITE_DATA',
        domain: activeDomain
      });

      if (response && response.siteData) {
        currentSiteData = response.siteData;
        renderDashboard(currentSiteData);
      } else {
        renderDefaultState();
      }
    } catch (err) {
      console.error('[Consent Ledger Popup] Load error:', err);
      renderNoWebpageState();
    }
  }

  function renderDashboard(data) {
    if (!data) return;

    // 1. Trust Score & Risk Level
    const score = data.trustScore ?? 100;
    elTrustScore.textContent = score;

    elScoreMeterFill.style.width = `${Math.min(100, Math.max(0, score))}%`;
    elScoreMeterFill.className = 'score-meter-fill';

    elRiskLevelBadge.className = 'risk-badge';
    if (score >= 80) {
      elRiskLevelBadge.textContent = 'LOW RISK';
      elRiskLevelBadge.classList.add('badge-low');
      elScoreMeterFill.classList.add('fill-low');
    } else if (score >= 50) {
      elRiskLevelBadge.textContent = 'MODERATE RISK';
      elRiskLevelBadge.classList.add('badge-mod');
      elScoreMeterFill.classList.add('fill-mod');
    } else {
      elRiskLevelBadge.textContent = 'HIGH RISK';
      elRiskLevelBadge.classList.add('badge-high');
      elScoreMeterFill.classList.add('fill-high');
    }

    // 2. Consent Status
    const consentState = data.consentState || 'UNKNOWN';
    elConsentStatusBadge.textContent = consentState;
    elConsentStatusBadge.className = 'status-badge';

    switch (consentState) {
      case 'ACCEPTED':
        elConsentStatusBadge.classList.add('status-accepted');
        break;
      case 'REJECTED':
        elConsentStatusBadge.classList.add('status-rejected');
        break;
      case 'CUSTOM':
        elConsentStatusBadge.classList.add('status-custom');
        break;
      default:
        if (data.consentInterface === 'NO_CONSENT_INTERFACE_DETECTED') {
          elConsentStatusBadge.textContent = 'NO CONSENT INTERFACE';
          elConsentStatusBadge.classList.add('status-silent');
        } else {
          elConsentStatusBadge.classList.add('status-unknown');
        }
    }

    // Subtext for consent interface
    if (data.consentInterface === 'CONSENT_INTERFACE_DETECTED') {
      elInterfaceStateText.textContent = 'Consent interface detected on page';
    } else if (data.consentInterface === 'NO_CONSENT_INTERFACE_DETECTED') {
      elInterfaceStateText.textContent = 'No detectable consent interface found';
    } else {
      elInterfaceStateText.textContent = 'Consent interface status pending / unconfirmed';
    }

    // 3. Activity Counts
    const trackerCount = (data.trackers || []).length;
    const violationCount = (data.evidenceLedger || []).length;

    elTrackersCount.textContent = trackerCount;
    elViolationsCount.textContent = violationCount;

    // 4. Latest Alert Card
    if (data.latestAlert) {
      elAlertCard.classList.add('has-violation');
      elLatestAlertStatus.textContent = 'Potential Violation';
      elLatestAlertStatus.classList.add('pill-active');

      elLatestAlertType.textContent = data.latestAlert.type || 'UNKNOWN';
      elLatestAlertTracker.textContent = data.latestAlert.tracker || 'UNKNOWN';
      elLatestAlertDetails.textContent = data.latestAlert.details || 'Suspicious tracking pattern detected.';
    } else {
      elAlertCard.classList.remove('has-violation');
      elLatestAlertStatus.textContent = 'No Alerts';
      elLatestAlertStatus.classList.remove('pill-active');

      elLatestAlertType.textContent = '—';
      elLatestAlertTracker.textContent = '—';
      elLatestAlertDetails.textContent = 'No suspicious tracking activity recorded for this session.';
    }
  }

  // ==========================================================================
  // EVIDENCE MODAL
  // ==========================================================================

  function renderEvidenceModal() {
    elEvidenceList.innerHTML = '';
    const records = currentSiteData?.evidenceLedger || [];

    if (records.length === 0) {
      elEvidenceList.innerHTML = `
        <div class="empty-state">
          <p>🛡 No potential violations recorded.</p>
          <span style="font-size: 11px; color: #6b7280; margin-top: 4px; display: block;">
            All monitored third-party activity is currently within expected consent boundaries.
          </span>
        </div>
      `;
      return;
    }

    records.forEach((record) => {
      const item = document.createElement('div');
      item.className = 'evidence-item';

      const formattedTime = new Date(record.timestamp).toLocaleTimeString();

      item.innerHTML = `
        <div class="evidence-header">
          <span class="evidence-id">${escapeHtml(record.evidenceId)}</span>
          <span class="evidence-type-badge">${escapeHtml(record.violationType)}</span>
        </div>
        <div class="evidence-field">
          <span class="evidence-field-label">Tracker:</span>
          <span class="evidence-field-val code-font">${escapeHtml(record.tracker)}</span>
        </div>
        <div class="evidence-field">
          <span class="evidence-field-label">Classification:</span>
          <span class="evidence-field-val">${escapeHtml(record.classification)}</span>
        </div>
        <div class="evidence-field">
          <span class="evidence-field-label">Consent:</span>
          <span class="evidence-field-val">${escapeHtml(record.consentState)}</span>
        </div>
        <div class="evidence-field">
          <span class="evidence-field-label">Observed:</span>
          <span class="evidence-field-val">${formattedTime}</span>
        </div>
        <div class="alert-details" style="margin-top: 4px;">
          ${escapeHtml(record.details)}
        </div>
        <div class="evidence-hash-box">
          <div class="hash-label-row">
            <span>SHA-256 Record Integrity Hash</span>
            <span class="hash-status-verified" id="hash-status-${escapeHtml(record.evidenceId)}">✓ Verified</span>
          </div>
          <div class="hash-value">${escapeHtml(record.evidenceHash || 'Computing...')}</div>
        </div>
      `;

      elEvidenceList.appendChild(item);

      // Async verify hash to ensure zero tampering
      if (record.evidenceHash) {
        chrome.runtime.sendMessage(
          { type: 'VERIFY_EVIDENCE', record },
          (response) => {
            const statusEl = document.getElementById(`hash-status-${record.evidenceId}`);
            if (statusEl) {
              if (response && response.isValid) {
                statusEl.textContent = '✓ Verified';
                statusEl.className = 'hash-status-verified';
              } else {
                statusEl.textContent = '⚠ Tampered';
                statusEl.style.color = 'var(--color-high-risk)';
              }
            }
          }
        );
      }
    });
  }

  // ==========================================================================
  // TIMELINE MODAL
  // ==========================================================================

  function renderTimelineModal() {
    elTimelineList.innerHTML = '';
    const timeline = currentSiteData?.timeline || [];

    if (timeline.length === 0) {
      elTimelineList.innerHTML = `
        <div class="empty-state">
          <p>⏱ No timeline events recorded yet.</p>
        </div>
      `;
      return;
    }

    // Render in reverse chronological order (newest first)
    const reversed = [...timeline].reverse();

    reversed.forEach((entry) => {
      const item = document.createElement('div');
      item.className = 'timeline-item';

      const formattedTime = new Date(entry.timestamp).toLocaleTimeString();

      item.innerHTML = `
        <div class="timeline-bullet"></div>
        <div class="timeline-content">
          <div class="timeline-title">${escapeHtml(entry.event)}</div>
          <div class="timeline-time">${formattedTime}</div>
          <div class="timeline-desc">${escapeHtml(entry.details)}</div>
        </div>
      `;

      elTimelineList.appendChild(item);
    });
  }

  // ==========================================================================
  // HELPER STATES & UTILITIES
  // ==========================================================================

  function renderNoWebpageState(protocol) {
    elWebsite.textContent = protocol ? `${protocol}// (Internal)` : 'No Active Web Page';
    elTrustScore.textContent = '100';
    elScoreMeterFill.style.width = '100%';
    elRiskLevelBadge.textContent = 'INACTIVE';
    elRiskLevelBadge.className = 'risk-badge';
    elConsentStatusBadge.textContent = 'N/A';
    elConsentStatusBadge.className = 'status-badge status-unknown';
    elInterfaceStateText.textContent = 'Active tab is not an inspectable HTTP/HTTPS webpage.';
    elTrackersCount.textContent = '0';
    elViolationsCount.textContent = '0';
    elLatestAlertStatus.textContent = 'Inactive';
    elLatestAlertType.textContent = '—';
    elLatestAlertTracker.textContent = '—';
    elLatestAlertDetails.textContent = 'Consent Ledger activates on public websites.';

    btnViewEvidence.disabled = true;
    btnViewTimeline.disabled = true;
    btnClearData.disabled = true;
  }

  function renderDefaultState() {
    elTrustScore.textContent = '100';
    elScoreMeterFill.style.width = '100%';
    elRiskLevelBadge.textContent = 'LOW RISK';
    elRiskLevelBadge.className = 'risk-badge badge-low';
    elConsentStatusBadge.textContent = 'UNKNOWN';
    elConsentStatusBadge.className = 'status-badge status-unknown';
    elInterfaceStateText.textContent = 'Scanning consent interface...';
    elTrackersCount.textContent = '0';
    elViolationsCount.textContent = '0';
  }

  function showToast(message) {
    elToast.textContent = message;
    elToast.classList.remove('hidden');
    setTimeout(() => {
      elToast.classList.add('hidden');
    }, 2000);
  }

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
})();
