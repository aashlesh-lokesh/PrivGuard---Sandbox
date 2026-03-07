/**
 * PrivGuard Content Script
 *
 * Monitors ALL text entry surfaces on every page:
 *   - <input type="text|email|search|url|tel|password">
 *   - <textarea>
 *   - [contenteditable] (Gmail compose, Notion, Slack, etc.)
 *   - <form> submit interception
 *   - <input type="file"> for image uploads (OCR)
 *
 * Uses the detection engine (inlined at build time via webpack)
 * to scan in real time, underline findings, show tooltip warnings,
 * and optionally redact before submission.
 */

(function () {
  'use strict';

  /* ═══════════════════════════════════════════════════════════════
     INLINE DETECTION ENGINE (bundled by webpack, see build step)
     We import it from the engine/ folder that ships with the extension.
     ═══════════════════════════════════════════════════════════════ */

  // The detection engine classes are loaded inline below this IIFE
  // by webpack. At runtime `window.__PrivGuardEngine` is available.
  // If running unbundled for dev, we lazy-load it.

  /* ═══════════════════════════════════════════════════════════════
     CONFIGURATION
     ═══════════════════════════════════════════════════════════════ */
  const SCAN_DEBOUNCE_MS   = 400;   // ms after last keystroke before scanning
  const MIN_TEXT_LENGTH    = 4;     // don't scan very short values
  const ATTR_SCANNED       = 'data-pg-scanned';
  const ATTR_FIELD_ID      = 'data-pg-field-id';
  const CLASS_HIGHLIGHT    = 'pg-highlight';
  const CLASS_TOOLTIP      = 'pg-tooltip';
  const CLASS_FIELD_WARN   = 'pg-field-warning';

  /* ═══════════════════════════════════════════════════════════════
     STATE
     ═══════════════════════════════════════════════════════════════ */
  let enabled        = true;
  let engine         = null;
  let fieldCounter   = 0;
  let fieldsScanned  = 0;
  let redactedCount  = 0;

  // Map<fieldId, { element, findings[], timer }>
  const fieldMap = new Map();

  // Aggregate findings across all fields for the popup
  function getAllFindings() {
    const all = [];
    for (const state of fieldMap.values()) {
      all.push(...(state.findings || []));
    }
    return all;
  }

  /* ═══════════════════════════════════════════════════════════════
     ENGINE INITIALISATION
     ═══════════════════════════════════════════════════════════════ */
  function getEngine() {
    if (engine) return engine;
    // Detection engine modules are concatenated into this file by the build
    // They expose: runRegexPatterns, NLPDetector, PrivacyScorer
    // For the content script we use a lightweight inline version
    // that skips OCR (OCR runs via background script for images)
    engine = createLightweightEngine();
    return engine;
  }

  /**
   * Lightweight engine that runs regex + NLP inline.
   * No OCR here — OCR is handled by the background script.
   */
  function createLightweightEngine() {
    // Import from the bundled engine globals if available
    if (typeof PrivGuardDetectionEngine !== 'undefined') {
      return new PrivGuardDetectionEngine({ enableNLP: true, enableOCR: false });
    }

    // Fallback: import from the patterns bundled inline below
    // (This is the path when the file is loaded as a standalone content script)
    return new InlineDetectionEngine();
  }

  /* ═══════════════════════════════════════════════════════════════
     INLINE MINIMAL ENGINE (fallback — patterns only, no deps)
     This is used when the full engine bundle isn't loaded.
     Provides regex scanning + simple scoring.
     ═══════════════════════════════════════════════════════════════ */
  class InlineDetectionEngine {
    constructor() {
      this._patterns = buildInlinePatterns();
      this._severityWeights = {
        CRITICAL: 70, HIGH: 40, MEDIUM: 20, LOW: 8,
      };
    }

    async analyzeText(text) {
      return this.analyze({ text });
    }

    async analyze({ text }) {
      if (!text || text.trim().length < MIN_TEXT_LENGTH) {
        return { score: 0, riskLevel: 'NONE', findings: [], redactedText: () => text || '' };
      }

      const findings = [];
      for (const p of this._patterns) {
        const re = new RegExp(p.pattern.source, p.pattern.flags);
        let m;
        while ((m = re.exec(text)) !== null) {
          const fullMatch = m[0];
          const captured = p.captureGroup != null ? m[p.captureGroup] : fullMatch;
          if (!captured) continue;
          if (p.validate && !p.validate(captured)) continue;

          const start = m.index;
          const end   = m.index + fullMatch.length;
          const dup   = findings.some(f => f.position.start <= start && f.position.end >= end);
          if (dup) continue;

          findings.push({
            id:         `${p.id}_${start}`,
            type:       p.type,
            label:      p.label,
            category:   p.category,
            severity:   p.severity,
            confidence: p.confidence,
            value:      captured,
            rawMatch:   fullMatch,
            redacted:   p.redact ? p.redact(captured) : '[REDACTED]',
            position:   { start, end },
            source:     'regex',
          });

          if (fullMatch.length === 0) re.lastIndex++;
        }
      }

      // Simple scoring
      let rawScore = 0;
      for (const f of findings) {
        rawScore += this._severityWeights[f.severity] || 10;
      }
      const score = Math.min(100, rawScore);
      const riskLevel = score >= 80 ? 'CRITICAL'
        : score >= 55 ? 'HIGH'
        : score >= 30 ? 'MEDIUM'
        : score >= 1  ? 'LOW'
        : 'NONE';

      return {
        score,
        riskLevel,
        findings: findings.sort((a, b) => a.position.start - b.position.start),
        redactedText: () => {
          let result = text;
          const sorted = [...findings].sort((a, b) => b.position.start - a.position.start);
          for (const f of sorted) {
            result = result.slice(0, f.position.start) + f.redacted + result.slice(f.position.end);
          }
          return result;
        },
      };
    }
  }

  /* ═══════════════════════════════════════════════════════════════
     Inline pattern definitions (subset for content script)
     ═══════════════════════════════════════════════════════════════ */
  function luhnCheck(numStr) {
    const digits = numStr.replace(/[\s\-]/g, '');
    if (!/^\d+$/.test(digits)) return false;
    let sum = 0, dbl = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = parseInt(digits[i], 10);
      if (dbl) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
      dbl = !dbl;
    }
    return sum % 10 === 0;
  }

  function buildInlinePatterns() {
    return [
      // Credit cards
      { id: 'VISA', type: 'CREDIT_CARD', label: 'Visa Card Number', category: 'financial', severity: 'HIGH', confidence: 0.95,
        pattern: /\b4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/g,
        validate: m => luhnCheck(m), redact: r => { const d = r.replace(/[\s\-]/g,''); return d.slice(0,4)+' **** **** '+d.slice(-4); }},
      { id: 'MC', type: 'CREDIT_CARD', label: 'Mastercard Number', category: 'financial', severity: 'HIGH', confidence: 0.95,
        pattern: /\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/g,
        validate: m => luhnCheck(m), redact: r => { const d = r.replace(/[\s\-]/g,''); return d.slice(0,4)+' **** **** '+d.slice(-4); }},
      { id: 'AMEX', type: 'CREDIT_CARD', label: 'Amex Card Number', category: 'financial', severity: 'HIGH', confidence: 0.95,
        pattern: /\b3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}\b/g,
        validate: m => luhnCheck(m), redact: r => { const d = r.replace(/[\s\-]/g,''); return d.slice(0,4)+' ****** '+d.slice(-5); }},

      // CVV
      { id: 'CVV', type: 'CVV', label: 'CVV / Security Code', category: 'financial', severity: 'HIGH', confidence: 0.85,
        pattern: /\b(?:cvv2?|cvc2?|cid|security[\s_-]?code|card[\s_-]?verif\w+)[\s:=]*([0-9]{3,4})\b/gi,
        captureGroup: 1, redact: () => '[CVV REDACTED]' },

      // SSN
      { id: 'SSN', type: 'SSN', label: 'Social Security Number', category: 'identity', severity: 'CRITICAL', confidence: 0.92,
        pattern: /\b(?!000|666|9\d{2})\d{3}[\s\-]?(?!00)\d{2}[\s\-]?(?!0000)\d{4}\b/g,
        validate: m => { const d = m.replace(/[\s\-]/g, ''); return !['123456789','111111111','222222222','333333333','444444444','555555555','666666666','777777777','888888888','999999999'].includes(d); },
        redact: r => { const d = r.replace(/[\s\-]/g,''); return '***-**-'+d.slice(-4); }},

      // Phone US
      { id: 'PHONE_US', type: 'PHONE_NUMBER', label: 'Phone Number', category: 'contact', severity: 'MEDIUM', confidence: 0.85,
        pattern: /\b(?:\+?1[\s.\-]?)?\(?(?:[2-9][0-8][0-9])\)?[\s.\-]?(?:[2-9][0-9]{2})[\s.\-]?(?:[0-9]{4})\b/g,
        validate: m => { const d = m.replace(/\D/g,''); const c = d.startsWith('1')&&d.length===11?d.slice(1):d; return c.length===10; },
        redact: r => { const d = r.replace(/\D/g,''); return '(***) ***-'+d.slice(-4); }},

      // Email
      { id: 'EMAIL', type: 'EMAIL', label: 'Email Address', category: 'contact', severity: 'LOW', confidence: 0.95,
        pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b/g,
        validate: m => { const l = m.toLowerCase(); return !['example.com','test.com','domain.com','email.com'].some(d => l.endsWith(d)); },
        redact: r => { const [l,d] = r.split('@'); return l[0]+'***@'+d; }},

      // AWS Key
      { id: 'AWS_KEY', type: 'AWS_ACCESS_KEY', label: 'AWS Access Key', category: 'credentials', severity: 'CRITICAL', confidence: 0.99,
        pattern: /\b(AKIA[0-9A-Z]{16})\b/g, redact: r => r.slice(0,4)+'...'+r.slice(-4) },

      // GitHub PAT
      { id: 'GH_PAT', type: 'GITHUB_TOKEN', label: 'GitHub Token', category: 'credentials', severity: 'CRITICAL', confidence: 0.99,
        pattern: /\b(ghp_[0-9a-zA-Z]{36})\b/g, redact: r => r.slice(0,8)+'...'+r.slice(-4) },

      // Google API
      { id: 'GAPI', type: 'GOOGLE_API_KEY', label: 'Google API Key', category: 'credentials', severity: 'HIGH', confidence: 0.99,
        pattern: /\b(AIza[0-9A-Za-z\-_]{35})\b/g, redact: r => r.slice(0,8)+'...'+r.slice(-4) },

      // Stripe
      { id: 'STRIPE', type: 'STRIPE_KEY', label: 'Stripe Key', category: 'credentials', severity: 'CRITICAL', confidence: 0.99,
        pattern: /\b(sk_live_[0-9a-zA-Z]{24,34})\b/g, redact: r => r.slice(0,8)+'...'+r.slice(-4) },

      // JWT
      { id: 'JWT', type: 'JWT_TOKEN', label: 'JWT Token', category: 'credentials', severity: 'HIGH', confidence: 0.97,
        pattern: /\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-+/=]*)\b/g,
        redact: () => '[JWT REDACTED]' },

      // PEM Private Key
      { id: 'PEM', type: 'PRIVATE_KEY', label: 'Private Key', category: 'credentials', severity: 'CRITICAL', confidence: 0.99,
        pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
        redact: () => '[PRIVATE KEY REDACTED]' },

      // Password
      { id: 'PASS', type: 'PASSWORD', label: 'Password', category: 'credentials', severity: 'HIGH', confidence: 0.80,
        pattern: /\b(?:password|passwd|pwd|pass|secret|credentials?)[\s]*[=:]["']?\s*([^\s"'}{,;]{6,})/gi,
        captureGroup: 1, redact: () => '[PASSWORD REDACTED]' },

      // URL with credentials
      { id: 'AUTH_URL', type: 'AUTH_URL', label: 'URL with Credentials', category: 'network', severity: 'CRITICAL', confidence: 0.97,
        pattern: /https?:\/\/[^:\s@/]+:[^@\s@/]+@[^\s"'<>){\]]+/gi,
        redact: r => r.replace(/(https?:\/\/)[^:\s@/]+:[^@\s@/]+@/, '$1[REDACTED]@') },

      // DB connection strings
      { id: 'DB_MONGO', type: 'DATABASE_URL', label: 'MongoDB Connection', category: 'network', severity: 'CRITICAL', confidence: 0.98,
        pattern: /mongodb(?:\+srv)?:\/\/[^\s"'<>){\]]+/gi,
        redact: r => r.replace(/:\/\/([^:\s@/]+):([^@\s@/]+)@/, '://[REDACTED]@') },
      { id: 'DB_PG', type: 'DATABASE_URL', label: 'PostgreSQL Connection', category: 'network', severity: 'CRITICAL', confidence: 0.98,
        pattern: /postgre(?:s|sql):\/\/[^\s"'<>){\]]+/gi,
        redact: r => r.replace(/:\/\/([^:\s@/]+):([^@\s@/]+)@/, '://[REDACTED]@') },

      // OTP
      { id: 'OTP', type: 'OTP', label: 'One-Time Password', category: 'credentials', severity: 'HIGH', confidence: 0.88,
        pattern: /\b(?:otp|one[\s\-]?time[\s\-]?(?:password|passcode|pin|code)|verification[\s\-]?code|auth(?:entication)?[\s\-]?code|2fa[\s\-]?code|security[\s\-]?code|confirm(?:ation)?[\s\-]?code)[\s:._\-]*(?:is\s+)?([0-9]{4,8})\b/gi,
        captureGroup: 1, redact: () => '[OTP REDACTED]' },

      // IBAN
      { id: 'IBAN', type: 'IBAN', label: 'IBAN Number', category: 'financial', severity: 'HIGH', confidence: 0.92,
        pattern: /\b[A-Z]{2}[0-9]{2}[\s]?(?:[A-Z0-9]{4}[\s]?){1,7}[A-Z0-9]{1,4}\b/g,
        validate: m => { const r = m.replace(/\s/g,''); return r.length >= 15 && r.length <= 34; },
        redact: r => r.slice(0,4)+' **** **** '+r.slice(-4) },

      // Aadhaar
      { id: 'AADHAAR', type: 'NATIONAL_ID', label: 'Aadhaar Number', category: 'identity', severity: 'CRITICAL', confidence: 0.88,
        pattern: /\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
        validate: m => m.replace(/[\s\-]/g, '').length === 12,
        redact: r => { const d = r.replace(/[\s\-]/g,''); return 'XXXX XXXX '+d.slice(-4); }},

      // Sensitive phrases
      { id: 'CONF_PHRASE', type: 'SENSITIVE_PHRASE', label: 'Confidential Phrase', category: 'context', severity: 'MEDIUM', confidence: 0.88,
        pattern: /\b(?:do not share|not for distribution|strictly confidential|for your eyes only|internal[\s\-]only|company[\s\-]confidential)\b/gi,
        redact: () => '[SENSITIVE CONTENT]' },
    ];
  }

  /* ═══════════════════════════════════════════════════════════════
     FIELD DISCOVERY & MONITORING
     ═══════════════════════════════════════════════════════════════ */

  const INPUT_SELECTORS = [
    'input[type="text"]',
    'input[type="email"]',
    'input[type="search"]',
    'input[type="url"]',
    'input[type="tel"]',
    'input[type="password"]',
    'input:not([type])',  // defaults to text
    'textarea',
    '[contenteditable="true"]',
    '[contenteditable=""]',
    '[role="textbox"]',
  ].join(', ');

  function discoverFields() {
    const elements = document.querySelectorAll(INPUT_SELECTORS);
    elements.forEach(attachField);
  }

  function attachField(el) {
    if (el.hasAttribute(ATTR_SCANNED)) return;

    const fieldId = `pg_field_${++fieldCounter}`;
    el.setAttribute(ATTR_SCANNED, '1');
    el.setAttribute(ATTR_FIELD_ID, fieldId);

    const state = { element: el, findings: [], timer: null, lastText: '' };
    fieldMap.set(fieldId, state);

    // Listen for input
    const handler = () => {
      if (!enabled) return;
      clearTimeout(state.timer);
      state.timer = setTimeout(() => scanField(fieldId), SCAN_DEBOUNCE_MS);
    };

    el.addEventListener('input', handler, { passive: true });
    el.addEventListener('keyup', handler, { passive: true });

    // Also listen for paste
    el.addEventListener('paste', () => {
      if (!enabled) return;
      setTimeout(() => scanField(fieldId), 50);
    }, { passive: true });

    // Initial scan if field already has content
    const text = getFieldText(el);
    if (text && text.length >= MIN_TEXT_LENGTH) {
      setTimeout(() => scanField(fieldId), 200);
    }
  }

  function getFieldText(el) {
    if (el.isContentEditable || el.getAttribute('contenteditable') !== null) {
      return el.innerText || el.textContent || '';
    }
    return el.value || '';
  }

  function setFieldText(el, text) {
    if (el.isContentEditable || el.getAttribute('contenteditable') !== null) {
      el.innerText = text;
    } else {
      el.value = text;
      // Dispatch input event so frameworks (React, Vue, Angular) pick up the change
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  /* ═══════════════════════════════════════════════════════════════
     SCANNING
     ═══════════════════════════════════════════════════════════════ */

  async function scanField(fieldId) {
    const state = fieldMap.get(fieldId);
    if (!state || !enabled) return;

    const text = getFieldText(state.element);

    // Skip if text hasn't changed
    if (text === state.lastText) return;
    state.lastText = text;

    if (!text || text.length < MIN_TEXT_LENGTH) {
      state.findings = [];
      clearFieldHighlights(state.element);
      broadcastState();
      return;
    }

    fieldsScanned++;
    const eng = getEngine();
    const result = await eng.analyzeText(text);

    state.findings = result.findings;

    // Visual feedback
    if (result.findings.length > 0) {
      state.element.classList.add(CLASS_FIELD_WARN);
      showFieldWarning(state.element, result);
    } else {
      clearFieldHighlights(state.element);
    }

    broadcastState();
  }

  // Scan all currently tracked fields
  async function scanAllFields() {
    for (const fieldId of fieldMap.keys()) {
      await scanField(fieldId);
    }
  }

  /* ═══════════════════════════════════════════════════════════════
     VISUAL INDICATORS
     ═══════════════════════════════════════════════════════════════ */

  function showFieldWarning(el, result) {
    // Remove existing tooltip
    removeTooltip(el);

    // Coloured border based on risk level
    const colors = {
      CRITICAL: '#D63031',
      HIGH:     '#E17055',
      MEDIUM:   '#FDCB6E',
      LOW:      '#00B894',
    };
    const color = colors[result.riskLevel] || colors.MEDIUM;
    el.style.setProperty('outline', `2px solid ${color}`, 'important');
    el.style.setProperty('outline-offset', '1px', 'important');

    // Tooltip
    const tooltip = document.createElement('div');
    tooltip.className = CLASS_TOOLTIP;
    tooltip.setAttribute('data-pg-tooltip', '1');
    tooltip.innerHTML = `
      <div class="pg-tt-header">
        <span class="pg-tt-icon">🛡️</span>
        <strong>PrivGuard Warning</strong>
        <span class="pg-tt-score" style="background:${color}">${result.score}</span>
      </div>
      <div class="pg-tt-body">
        ${result.findings.slice(0, 3).map(f => `
          <div class="pg-tt-item">
            <span class="pg-tt-sev" style="color:${colors[f.severity] || '#ccc'}">${getSeverityIcon(f.severity)}</span>
            <span>${escHtml(f.label)}: <code>${escHtml(truncateStr(f.value, 20))}</code></span>
          </div>
        `).join('')}
        ${result.findings.length > 3 ? `<div class="pg-tt-more">+${result.findings.length - 3} more items</div>` : ''}
      </div>
      <div class="pg-tt-actions">
        <button class="pg-tt-btn pg-tt-btn-redact">Redact All</button>
        <button class="pg-tt-btn pg-tt-btn-dismiss">Dismiss</button>
      </div>
    `;

    // Position the tooltip
    document.body.appendChild(tooltip);
    positionTooltip(tooltip, el);

    // Event handlers
    tooltip.querySelector('.pg-tt-btn-redact')?.addEventListener('click', (e) => {
      e.stopPropagation();
      redactField(el.getAttribute(ATTR_FIELD_ID));
      removeTooltip(el);
    });

    tooltip.querySelector('.pg-tt-btn-dismiss')?.addEventListener('click', (e) => {
      e.stopPropagation();
      removeTooltip(el);
    });

    // Auto-hide after 8 seconds
    setTimeout(() => removeTooltip(el), 8000);
  }

  function positionTooltip(tooltip, el) {
    const rect = el.getBoundingClientRect();
    const scrollY = window.scrollY || document.documentElement.scrollTop;
    const scrollX = window.scrollX || document.documentElement.scrollLeft;

    tooltip.style.position = 'absolute';
    tooltip.style.zIndex   = '2147483647';
    tooltip.style.top      = `${rect.bottom + scrollY + 6}px`;
    tooltip.style.left     = `${rect.left + scrollX}px`;
    tooltip.style.maxWidth = `${Math.min(360, rect.width + 40)}px`;

    // If overflowing bottom, show above
    requestAnimationFrame(() => {
      const ttRect = tooltip.getBoundingClientRect();
      if (ttRect.bottom > window.innerHeight) {
        tooltip.style.top = `${rect.top + scrollY - ttRect.height - 6}px`;
      }
    });
  }

  function removeTooltip(el) {
    document.querySelectorAll(`[data-pg-tooltip]`).forEach(t => t.remove());
    if (el) {
      el.style.removeProperty('outline');
      el.style.removeProperty('outline-offset');
    }
  }

  function clearFieldHighlights(el) {
    el.classList.remove(CLASS_FIELD_WARN);
    removeTooltip(el);
  }

  // ── Helpers ──────────────────────────────────────────────
  function getSeverityIcon(severity) {
    return { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' }[severity] || '⚪';
  }

  function escHtml(str) {
    if (!str) return '';
    const el = document.createElement('span');
    el.textContent = String(str);
    return el.innerHTML;
  }

  function truncateStr(str, max) {
    return (!str || str.length <= max) ? (str || '') : str.slice(0, max) + '…';
  }

  /* ═══════════════════════════════════════════════════════════════
     REDACTION
     ═══════════════════════════════════════════════════════════════ */

  function redactField(fieldId) {
    const state = fieldMap.get(fieldId);
    if (!state || !state.findings.length) return;

    const text = getFieldText(state.element);
    // Apply redactions in reverse order to preserve positions
    const sorted = [...state.findings].sort((a, b) => b.position.start - a.position.start);
    let result = text;
    for (const f of sorted) {
      result = result.slice(0, f.position.start) + f.redacted + result.slice(f.position.end);
    }

    setFieldText(state.element, result);
    redactedCount += state.findings.length;
    state.findings = [];
    state.lastText = result;
    clearFieldHighlights(state.element);
    broadcastState();
  }

  function redactAll() {
    for (const fieldId of fieldMap.keys()) {
      redactField(fieldId);
    }
  }

  function redactSingle(findingId) {
    for (const [fieldId, state] of fieldMap.entries()) {
      const finding = state.findings.find(f => f.id === findingId);
      if (finding) {
        const text = getFieldText(state.element);
        const result = text.slice(0, finding.position.start) + finding.redacted + text.slice(finding.position.end);
        setFieldText(state.element, result);
        redactedCount++;
        // Re-scan to update positions
        state.lastText = ''; // force re-scan
        scanField(fieldId);
        break;
      }
    }
  }

  /* ═══════════════════════════════════════════════════════════════
     FORM SUBMIT INTERCEPTION
     ═══════════════════════════════════════════════════════════════ */

  function interceptFormSubmits() {
    document.addEventListener('submit', async (e) => {
      if (!enabled) return;

      const form = e.target;
      const inputs = form.querySelectorAll(INPUT_SELECTORS);
      let hasFindings = false;

      for (const input of inputs) {
        const fieldId = input.getAttribute(ATTR_FIELD_ID);
        if (fieldId) {
          const state = fieldMap.get(fieldId);
          if (state && state.findings.length > 0) {
            hasFindings = true;
            break;
          }
        }
      }

      if (hasFindings) {
        e.preventDefault();
        e.stopImmediatePropagation();
        showSubmitWarning(form);
      }
    }, true);
  }

  function showSubmitWarning(form) {
    // Create a modal overlay
    const overlay = document.createElement('div');
    overlay.className = 'pg-submit-overlay';
    overlay.innerHTML = `
      <div class="pg-submit-modal">
        <div class="pg-modal-icon">🛡️</div>
        <h2>PrivGuard Alert</h2>
        <p>Sensitive data detected in this form! Review before submitting.</p>
        <div class="pg-modal-actions">
          <button class="pg-modal-btn pg-modal-btn-redact">Redact & Submit</button>
          <button class="pg-modal-btn pg-modal-btn-submit">Submit Anyway</button>
          <button class="pg-modal-btn pg-modal-btn-cancel">Cancel</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    overlay.querySelector('.pg-modal-btn-redact').addEventListener('click', () => {
      redactAll();
      overlay.remove();
      form.submit();
    });

    overlay.querySelector('.pg-modal-btn-submit').addEventListener('click', () => {
      overlay.remove();
      form.submit();
    });

    overlay.querySelector('.pg-modal-btn-cancel').addEventListener('click', () => {
      overlay.remove();
    });
  }

  /* ═══════════════════════════════════════════════════════════════
     FILE UPLOAD SCANNING (IMAGE OCR via background script)
     ═══════════════════════════════════════════════════════════════ */

  function monitorFileUploads() {
    document.addEventListener('change', (e) => {
      if (!enabled) return;
      const input = e.target;
      if (input.tagName !== 'INPUT' || input.type !== 'file') return;

      const files = input.files;
      if (!files || files.length === 0) return;

      for (const file of files) {
        if (file.type.startsWith('image/')) {
          scanImageFile(file, input);
        }
      }
    }, { passive: true });
  }

  async function scanImageFile(file, inputEl) {
    // Send to background script for OCR processing
    const reader = new FileReader();
    reader.onload = () => {
      chrome.runtime.sendMessage({
        type: 'PG_SCAN_IMAGE',
        dataUrl: reader.result,
      }, (response) => {
        if (response && response.findings && response.findings.length > 0) {
          showImageWarning(inputEl, response);
        }
      });
    };
    reader.readAsDataURL(file);
  }

  function showImageWarning(inputEl, result) {
    const fieldId = `pg_img_${++fieldCounter}`;
    inputEl.setAttribute(ATTR_FIELD_ID, fieldId);
    const state = { element: inputEl, findings: result.findings, timer: null, lastText: '' };
    fieldMap.set(fieldId, state);
    showFieldWarning(inputEl, result);
    broadcastState();
  }

  /* ═══════════════════════════════════════════════════════════════
     MUTATION OBSERVER (for dynamically added fields)
     ═══════════════════════════════════════════════════════════════ */

  function observeDOM() {
    const observer = new MutationObserver((mutations) => {
      let shouldDiscover = false;
      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          shouldDiscover = true;
          break;
        }
      }
      if (shouldDiscover) discoverFields();
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  /* ═══════════════════════════════════════════════════════════════
     MESSAGING (content ↔ popup ↔ background)
     ═══════════════════════════════════════════════════════════════ */

  function broadcastState() {
    const findings = getAllFindings();
    const eng = getEngine();

    // Compute aggregate score
    let rawScore = 0;
    const weights = { CRITICAL: 70, HIGH: 40, MEDIUM: 20, LOW: 8 };
    for (const f of findings) rawScore += weights[f.severity] || 10;
    const score = Math.min(100, rawScore);
    const riskLevel = score >= 80 ? 'CRITICAL' : score >= 55 ? 'HIGH' : score >= 30 ? 'MEDIUM' : score >= 1 ? 'LOW' : 'NONE';

    const data = {
      score,
      riskLevel,
      findings,
      fieldsScanned,
      redacted: redactedCount,
    };

    // Send to popup
    chrome.runtime.sendMessage({ type: 'PG_STATE_UPDATE', data }).catch(() => {});

    // Also update badge via background
    chrome.runtime.sendMessage({
      type: 'PG_UPDATE_BADGE',
      score,
      riskLevel,
      findingsCount: findings.length,
    }).catch(() => {});
  }

  // Listen for messages from popup
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    switch (msg.type) {
      case 'PG_REQUEST_STATE':
        broadcastState();
        break;
      case 'PG_TOGGLE':
        enabled = msg.enabled;
        if (!enabled) {
          // Clear all highlights
          for (const state of fieldMap.values()) {
            clearFieldHighlights(state.element);
            state.findings = [];
          }
          broadcastState();
        } else {
          scanAllFields();
        }
        break;
      case 'PG_REDACT_ALL':
        redactAll();
        break;
      case 'PG_REDACT_SINGLE':
        redactSingle(msg.findingId);
        break;
    }
  });

  /* ═══════════════════════════════════════════════════════════════
     BOOTSTRAP
     ═══════════════════════════════════════════════════════════════ */

  async function boot() {
    // Check if extension is enabled
    const { pgEnabled = true } = await chrome.storage.local.get('pgEnabled');
    enabled = pgEnabled;

    // Discover existing fields
    discoverFields();

    // Start observing for dynamically added fields
    observeDOM();

    // Intercept form submissions
    interceptFormSubmits();

    // Monitor file uploads
    monitorFileUploads();

    // Broadcast initial state
    setTimeout(broadcastState, 500);
  }

  // Don't run inside the extension's own pages
  if (window.location.protocol !== 'chrome-extension:') {
    boot();
  }

})();
