/**
 * PrivGuard Popup Controller
 * Communicates with the content script via chrome.tabs.sendMessage
 * to display real-time scan results.
 */

(function () {
  'use strict';

  // ── DOM refs ───────────────────────────────────────────
  const masterToggle  = document.getElementById('masterToggle');
  const scoreRing     = document.getElementById('scoreRing');
  const scoreValue    = document.getElementById('scoreValue');
  const riskBadge     = document.getElementById('riskBadge');
  const riskText      = document.getElementById('riskText');
  const statFindings  = document.getElementById('statFindings');
  const statFields    = document.getElementById('statFields');
  const statRedacted  = document.getElementById('statRedacted');
  const findingsList  = document.getElementById('findingsList');
  const emptyState    = document.getElementById('emptyState');
  const btnRedactAll  = document.getElementById('btnRedactAll');

  const RING_CIRCUMFERENCE = 326.73; // 2 * π * 52

  // ── Severity icon map ──────────────────────────────────
  const SEVERITY_ICONS = {
    CRITICAL: '🔴',
    HIGH:     '🟠',
    MEDIUM:   '🟡',
    LOW:      '🟢',
  };

  // ── State ──────────────────────────────────────────────
  let currentFindings = [];
  let redactedCount   = 0;

  // ── Init ───────────────────────────────────────────────
  async function init() {
    // Restore toggle
    const { pgEnabled = true } = await chrome.storage.local.get('pgEnabled');
    masterToggle.checked = pgEnabled;
    document.body.classList.toggle('pg-disabled', !pgEnabled);

    masterToggle.addEventListener('change', async () => {
      const enabled = masterToggle.checked;
      await chrome.storage.local.set({ pgEnabled: enabled });
      document.body.classList.toggle('pg-disabled', !enabled);
      sendToActiveTab({ type: 'PG_TOGGLE', enabled });
    });

    // Request current state from content script
    sendToActiveTab({ type: 'PG_REQUEST_STATE' });

    // Redact all
    btnRedactAll.addEventListener('click', () => {
      sendToActiveTab({ type: 'PG_REDACT_ALL' });
    });

    // Listen for updates from content script
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg.type === 'PG_STATE_UPDATE') {
        updateUI(msg.data);
      }
    });
  }

  // ── Send message to active tab ─────────────────────────
  function sendToActiveTab(message) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, message).catch(() => {});
      }
    });
  }

  // ── Update the popup UI ────────────────────────────────
  function updateUI(data) {
    if (!data) return;

    const { score = 0, riskLevel = 'NONE', findings = [], fieldsScanned = 0, redacted = 0 } = data;

    // Score ring
    const offset = RING_CIRCUMFERENCE - (score / 100) * RING_CIRCUMFERENCE;
    scoreRing.style.strokeDashoffset = offset;
    scoreValue.textContent = score;

    // Ring colour
    const ringColor = getRingColor(riskLevel);
    scoreRing.style.stroke = ringColor;
    scoreValue.style.background = `linear-gradient(135deg, ${ringColor}, ${ringColor})`;
    scoreValue.style.webkitBackgroundClip = 'text';

    // Risk badge
    riskBadge.dataset.level = riskLevel;
    riskText.textContent = riskLevel === 'NONE' ? 'SAFE' : riskLevel;

    // Stats
    statFindings.textContent = findings.length;
    statFields.textContent   = fieldsScanned;
    redactedCount = redacted;
    statRedacted.textContent = redactedCount;

    // Findings list
    currentFindings = findings;
    renderFindings(findings);

    // Redact-all button
    btnRedactAll.disabled = findings.length === 0;
  }

  // ── Render findings cards ──────────────────────────────
  function renderFindings(findings) {
    if (!findings.length) {
      findingsList.innerHTML = '';
      findingsList.appendChild(createEmptyState());
      return;
    }

    findingsList.innerHTML = '';
    emptyState?.remove();

    findings.forEach((f, idx) => {
      const card = document.createElement('div');
      card.className = 'pg-finding';
      card.innerHTML = `
        <div class="pg-finding-icon" data-severity="${esc(f.severity)}">
          ${SEVERITY_ICONS[f.severity] || '⚪'}
        </div>
        <div class="pg-finding-body">
          <div class="pg-finding-label">${esc(f.label)}</div>
          <div class="pg-finding-value" title="${esc(f.value)}">${esc(truncate(f.value, 36))}</div>
        </div>
        <span class="pg-finding-badge" data-severity="${esc(f.severity)}">${esc(f.severity)}</span>
        <button class="pg-btn-redact" title="Redact this item" data-index="${idx}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
            <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
            <line x1="1" y1="1" x2="23" y2="23"/>
          </svg>
        </button>
      `;

      card.querySelector('.pg-btn-redact').addEventListener('click', () => {
        sendToActiveTab({ type: 'PG_REDACT_SINGLE', findingId: f.id });
      });

      findingsList.appendChild(card);
    });
  }

  function createEmptyState() {
    const el = document.createElement('div');
    el.className = 'pg-empty-state';
    el.innerHTML = `
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#b2bec3" stroke-width="1.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <p>No sensitive data detected</p>
      <span>Start typing in any input field — PrivGuard monitors automatically.</span>
    `;
    return el;
  }

  // ── Helpers ────────────────────────────────────────────
  function getRingColor(level) {
    const map = {
      NONE:     '#636e72',
      LOW:      '#00B894',
      MEDIUM:   '#FDCB6E',
      HIGH:     '#E17055',
      CRITICAL: '#D63031',
    };
    return map[level] || map.NONE;
  }

  function truncate(str, max) {
    if (!str) return '';
    return str.length > max ? str.slice(0, max) + '…' : str;
  }

  function esc(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  init();
})();
