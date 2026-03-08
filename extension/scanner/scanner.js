/**
 * PrivGuard Image Scanner
 *
 * Two scan modes:
 *   Local  — Tesseract.js OCR + regex patterns (fully offline)
 *   NVIDIA — Tesseract.js for word positions + NVIDIA NIM vision LLM for
 *            semantic PII detection (images sent to NVIDIA servers)
 */

(function () {
  'use strict';

  /* ═══════════════════════════════════════════════════════════
     DOM REFS
     ═══════════════════════════════════════════════════════════ */
  const uploadZone      = document.getElementById('uploadZone');
  const fileInput       = document.getElementById('fileInput');
  const progressSection = document.getElementById('progressSection');
  const progressRing    = document.getElementById('progressRing');
  const progressPct     = document.getElementById('progressPct');
  const progressLabel   = document.getElementById('progressLabel');
  const resultsSection  = document.getElementById('resultsSection');
  const findingsCount   = document.getElementById('findingsCount');
  const wordsScanned    = document.getElementById('wordsScanned');
  const riskLevelEl     = document.getElementById('riskLevel');
  const findingsPanel   = document.getElementById('findingsPanel');
  const canvasOriginal  = document.getElementById('canvasOriginal');
  const canvasProtected = document.getElementById('canvasProtected');
  const btnDownload     = document.getElementById('btnDownload');
  const btnNewScan      = document.getElementById('btnNewScan');
  const modeLocalBtn    = document.getElementById('modeLocal');
  const modeNvidiaBtn   = document.getElementById('modeNvidia');
  const apiPanel        = document.getElementById('apiPanel');
  const apiKeyInput     = document.getElementById('apiKeyInput');
  const btnSaveKey      = document.getElementById('btnSaveKey');
  const apiKeyStatus    = document.getElementById('apiKeyStatus');
  const headerSubtitle  = document.getElementById('headerSubtitle');
  const footerNote      = document.getElementById('footerNote');

  const RING_CIRCUMFERENCE = 2 * Math.PI * 42; // ~263.89

  /* ═══════════════════════════════════════════════════════════
     SETTINGS
     ═══════════════════════════════════════════════════════════ */
  let scannerMode  = 'local';  // 'local' | 'nvidia'
  let nvidiaApiKey = '';

  async function loadSettings() {
    try {
      const stored = await chrome.storage.local.get(['pgScannerMode', 'pgNvidiaApiKey']);
      scannerMode  = stored.pgScannerMode  || 'local';
      nvidiaApiKey = stored.pgNvidiaApiKey || '';
    } catch { /* extension context not available (e.g., opened as plain tab) */ }
    updateSettingsUI();
  }

  async function saveSettings() {
    try {
      await chrome.storage.local.set({ pgScannerMode: scannerMode, pgNvidiaApiKey: nvidiaApiKey });
    } catch { /* ignore */ }
  }

  function updateSettingsUI() {
    const isNvidia = scannerMode === 'nvidia';

    modeLocalBtn.classList.toggle('pg-mode-active', !isNvidia);
    modeNvidiaBtn.classList.toggle('pg-mode-active',  isNvidia);
    apiPanel.hidden = !isNvidia;

    if (isNvidia) {
      headerSubtitle.textContent = 'Nemotron PII detection — only OCR text is sent to NVIDIA (no images)';
      footerNote.textContent = '⚠️ Nemotron mode: only the extracted text is sent to NVIDIA — your image never leaves the browser.';
      if (nvidiaApiKey) {
        apiKeyInput.value = nvidiaApiKey;
        apiKeyStatus.textContent = '✅ API key saved';
      } else {
        apiKeyStatus.innerHTML = 'Get a free key at <strong>build.nvidia.com</strong> → API Key';
      }
    } else {
      headerSubtitle.textContent = 'Detect & blur sensitive data in images — all processing is local';
      footerNote.textContent = 'All OCR & blurring happens locally in your browser — nothing is uploaded anywhere.';
    }
  }

  modeLocalBtn.addEventListener('click', () => {
    scannerMode = 'local';
    saveSettings();
    updateSettingsUI();
  });

  modeNvidiaBtn.addEventListener('click', () => {
    scannerMode = 'nvidia';
    saveSettings();
    updateSettingsUI();
  });

  btnSaveKey.addEventListener('click', () => {
    const key = apiKeyInput.value.trim();
    if (!key) return;
    nvidiaApiKey = key;
    saveSettings();
    apiKeyStatus.textContent = '✅ API key saved';
    btnSaveKey.textContent = 'Saved!';
    btnSaveKey.classList.add('pg-saved');
    setTimeout(() => {
      btnSaveKey.textContent = 'Save';
      btnSaveKey.classList.remove('pg-saved');
    }, 2000);
  });

  // Allow saving with Enter
  apiKeyInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') btnSaveKey.click(); });

  /* ═══════════════════════════════════════════════════════════
     DETECTION PATTERNS (shared with content script)
     ═══════════════════════════════════════════════════════════ */

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

  function redactKeepLastNDigits(raw, n) {
    const digits = raw.replace(/\D/g, '');
    if (digits.length <= n) return digits;
    return 'x'.repeat(digits.length - n) + digits.slice(-n);
  }

  const PATTERNS = [
    // Credit cards
    { id: 'VISA', label: 'Visa Card Number', severity: 'HIGH', confidence: 0.95,
      pattern: /\b4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/g,
      validate: m => luhnCheck(m), redact: r => redactKeepLastNDigits(r, 2) },
    { id: 'MC', label: 'Mastercard Number', severity: 'HIGH', confidence: 0.95,
      pattern: /\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/g,
      validate: m => luhnCheck(m), redact: r => redactKeepLastNDigits(r, 2) },
    { id: 'AMEX', label: 'Amex Card Number', severity: 'HIGH', confidence: 0.95,
      pattern: /\b3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}\b/g,
      validate: m => luhnCheck(m), redact: r => redactKeepLastNDigits(r, 2) },

    // SSN
    { id: 'SSN', label: 'Social Security Number', severity: 'CRITICAL', confidence: 0.92,
      pattern: /\b(?!000|666|9\d{2})\d{3}[\s\-]?(?!00)\d{2}[\s\-]?(?!0000)\d{4}\b/g,
      validate: m => { const d = m.replace(/[\s\-]/g, ''); return !['123456789','111111111','222222222','333333333','444444444','555555555','666666666','777777777','888888888','999999999'].includes(d); },
      redact: r => redactKeepLastNDigits(r, 2) },

    // Phone US
    { id: 'PHONE_US', label: 'Phone Number (US)', severity: 'MEDIUM', confidence: 0.85,
      pattern: /\b(?:\+?1[\s.\-]?)?\(?(?:[2-9][0-8][0-9])\)?[\s.\-]?(?:[2-9][0-9]{2})[\s.\-]?(?:[0-9]{4})\b/g,
      validate: m => { const d = m.replace(/\D/g, ''); const c = d.startsWith('1') && d.length === 11 ? d.slice(1) : d; return c.length === 10; },
      redact: r => { const d = r.replace(/\D/g, ''); return 'x'.repeat(d.length - 2) + d.slice(-2); } },

    // Phone IN
    { id: 'PHONE_IN', label: 'Phone Number (IN)', severity: 'MEDIUM', confidence: 0.88,
      pattern: /\b(?:\+?91[\s.\-]?)?[6-9]\d{4}[\s.\-]?\d{5}\b/g,
      validate: m => { const d = m.replace(/\D/g, ''); const c = d.startsWith('91') && d.length === 12 ? d.slice(2) : d; return c.length === 10; },
      redact: r => { const d = r.replace(/\D/g, ''); return 'x'.repeat(d.length - 2) + d.slice(-2); } },

    // Email
    { id: 'EMAIL', label: 'Email Address', severity: 'LOW', confidence: 0.95,
      pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b/g,
      validate: m => { const l = m.toLowerCase(); return !['example.com','test.com','domain.com','email.com'].some(d => l.endsWith(d)); } },

    // AWS Key
    { id: 'AWS_KEY', label: 'AWS Access Key', severity: 'CRITICAL', confidence: 0.99,
      pattern: /\b(AKIA[0-9A-Z]{16})\b/g },

    // GitHub PAT
    { id: 'GH_PAT', label: 'GitHub Token', severity: 'CRITICAL', confidence: 0.99,
      pattern: /\b(ghp_[0-9a-zA-Z]{36})\b/g },

    // Stripe
    { id: 'STRIPE', label: 'Stripe Key', severity: 'CRITICAL', confidence: 0.99,
      pattern: /\b(sk_live_[0-9a-zA-Z]{24,34})\b/g },

    // IBAN
    { id: 'IBAN', label: 'IBAN Number', severity: 'HIGH', confidence: 0.92,
      pattern: /\b[A-Z]{2}[0-9]{2}[\s]?(?:[A-Z0-9]{4}[\s]?){1,7}[A-Z0-9]{1,4}\b/g,
      validate: m => { const r = m.replace(/\s/g, ''); return r.length >= 15 && r.length <= 34; } },

    // Aadhaar
    { id: 'AADHAAR', label: 'Aadhaar Number', severity: 'CRITICAL', confidence: 0.88,
      pattern: /\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
      validate: m => m.replace(/[\s\-]/g, '').length === 12 },
  ];

  const SEVERITY_WEIGHTS = { CRITICAL: 70, HIGH: 40, MEDIUM: 20, LOW: 8 };
  const SEVERITY_ICONS   = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };

  /* ═══════════════════════════════════════════════════════════
     UPLOAD HANDLING
     ═══════════════════════════════════════════════════════════ */

  uploadZone.addEventListener('click', () => fileInput.click());

  uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('pg-dragover');
  });

  uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('pg-dragover');
  });

  uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('pg-dragover');
    const file = e.dataTransfer.files[0];
    if (file && file.type.startsWith('image/')) {
      processImage(file);
    }
  });

  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    if (file) processImage(file);
  });

  btnNewScan.addEventListener('click', resetToUpload);

  btnDownload.addEventListener('click', () => {
    const link = document.createElement('a');
    link.download = 'privguard-protected.png';
    link.href = canvasProtected.toDataURL('image/png');
    link.click();
  });

  /* ═══════════════════════════════════════════════════════════
     MAIN PIPELINE
     ═══════════════════════════════════════════════════════════ */

  async function processImage(file) {
    showProgress();

    try {
      // 1 — Load image
      updateProgress(5, 'Loading image…');
      const img = await loadImage(file);

      // 2 — Draw original on both canvases
      drawOnCanvas(canvasOriginal, img);
      drawOnCanvas(canvasProtected, img);

      // 3 — Tesseract OCR (always runs — provides word bounding boxes for blurring)
      updateProgress(10, 'Starting OCR engine…');
      const ocrResult = await runOCR(img);

      // 4 — Detect sensitive data (branch by mode)
      let findings;
      if (scannerMode === 'nvidia') {
        if (!nvidiaApiKey) {
          throw new Error('No NVIDIA API key saved. Switch to NVIDIA Nemotron mode and save your key first.');
        }
        const ocrText = ocrResult.text || '';
        if (!ocrText.trim()) {
          throw new Error('No text found in image. Nemotron needs OCR text to analyze.');
        }
        updateProgress(82, 'Sending OCR text to Nemotron for PII analysis…');
        let nemotronFindings = [];
        try {
          const rawFindings = await runNemotronTextScan(ocrText);
          nemotronFindings = matchFindingsToOcrBoxes(rawFindings, ocrResult);
          console.log('[PrivGuard] Nemotron found', nemotronFindings.length, 'items');
        } catch (nemErr) {
          console.warn('[PrivGuard] Nemotron call failed, falling back to local:', nemErr);
        }
        // Always run local regex too and merge (Nemotron may miss OCR-friendly patterns)
        updateProgress(90, 'Running local pattern scan…');
        const localFindings = detectSensitiveData(ocrResult);
        console.log('[PrivGuard] Local regex found', localFindings.length, 'items');
        // Merge: Nemotron first, then local findings that don't overlap
        findings = mergeFindings(nemotronFindings, localFindings);
      } else {
        updateProgress(85, 'Detecting sensitive data…');
        findings = detectSensitiveData(ocrResult);
      }

      // 5 — Blur sensitive regions on canvas
      updateProgress(95, 'Applying blur protection…');
      if (findings.length > 0) {
        blurSensitiveRegions(canvasProtected, img, findings);
      }

      // 6 — Show results
      updateProgress(100, 'Done!');
      setTimeout(() => showResults(ocrResult, findings), 400);

    } catch (err) {
      console.error('[PrivGuard Scanner] Error:', err);
      const msg = (err && (err.message || err.toString())) || 'Unknown error occurred';
      updateProgress(0, 'Error: ' + msg);
    }
  }

  /* ═══════════════════════════════════════════════════════════
     IMAGE LOADING
     ═══════════════════════════════════════════════════════════ */

  function loadImage(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => reject(new Error('Failed to load image'));
        img.src = reader.result;
      };
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsDataURL(file);
    });
  }

  function drawOnCanvas(canvas, img) {
    const ctx = canvas.getContext('2d');
    canvas.width = img.naturalWidth;
    canvas.height = img.naturalHeight;
    ctx.drawImage(img, 0, 0);
  }

  /* ═══════════════════════════════════════════════════════════
     OCR (Tesseract.js)
     ═══════════════════════════════════════════════════════════ */

  async function runOCR(img) {
    const workerPath = chrome.runtime.getURL('lib/worker.min.js');
    const corePath   = chrome.runtime.getURL('lib/tesseract-core-simd-lstm.wasm.js');

    const worker = await Tesseract.createWorker('eng', 1, {
      workerPath,
      corePath,
      workerBlobURL: false,
      logger: (m) => {
        if (m.status === 'recognizing text') {
          const pct = Math.round(10 + m.progress * 70); // 10–80%
          updateProgress(pct, 'Recognizing text… ' + Math.round(m.progress * 100) + '%');
        } else if (m.status === 'loading tesseract core') {
          updateProgress(8, 'Loading OCR core…');
        } else if (m.status === 'initializing tesseract') {
          updateProgress(12, 'Initializing OCR…');
        } else if (m.status === 'loading language traineddata') {
          updateProgress(15, 'Loading language data…');
        } else if (m.status === 'initializing api') {
          updateProgress(20, 'Preparing text recognition…');
        }
      },
    });

    const { data } = await worker.recognize(img.src);
    await worker.terminate();
    return data;
  }

  /* ═══════════════════════════════════════════════════════════
     NVIDIA NIM — NEMOTRON TEXT API
     Model: nvidia/llama-3.3-nemotron-super-49b-v1
     Only OCR-extracted text is sent to NVIDIA (not the image).
     Tesseract provides word bounding boxes for blurring.
     ═══════════════════════════════════════════════════════════ */

  const NVIDIA_API_URL = 'https://integrate.api.nvidia.com/v1/chat/completions';
  const NVIDIA_MODEL   = 'nvidia/llama-3.3-nemotron-super-49b-v1';

  const NVIDIA_PROMPT = `You are PrivGuard, a PII detection system. Analyze the user-provided text (extracted via OCR from an image) and identify every piece of sensitive or personally identifiable information.

Detect these types:
- Credit/debit card numbers, CVV, expiry dates
- Bank account numbers, IBAN, SWIFT/BIC codes
- SSN, Aadhaar numbers, national IDs, passport numbers
- Phone numbers, email addresses, physical addresses
- Passwords, PINs, OTPs, security codes
- API keys, access tokens, private keys, credentials
- Medical record numbers, health insurance IDs
- Driver's license numbers, vehicle registration numbers
- Dates of birth, tax IDs, financial account numbers

Return the exact text as it appears in the input — do not correct OCR errors.

Severity: CRITICAL (SSN, Aadhaar, card numbers, passwords, keys), HIGH (IBAN, bank accounts, OTP, medical IDs), MEDIUM (phone, email, address), LOW (names, generic contact info).

Respond with ONLY a JSON array, no other text:
[{"label":"<type>","value":"<exact text>","severity":"<CRITICAL|HIGH|MEDIUM|LOW>"}]

If nothing found, respond: []`;

  async function runNemotronTextScan(ocrText) {
    const response = await fetch(NVIDIA_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${nvidiaApiKey}`,
      },
      body: JSON.stringify({
        model: NVIDIA_MODEL,
        messages: [
          { role: 'system', content: NVIDIA_PROMPT },
          { role: 'user',   content: ocrText },
        ],
        max_tokens: 2048,
        temperature: 0.1,
      }),
    });

    if (!response.ok) {
      const errBody = await response.text().catch(() => '');
      if (response.status === 401) throw new Error('Invalid NVIDIA API key. Check your key in the settings above.');
      if (response.status === 402) throw new Error('NVIDIA API credits exhausted. Add credits at build.nvidia.com.');
      if (response.status === 429) throw new Error('NVIDIA API rate limit reached. Please wait a moment and try again.');
      let detail = '';
      try { detail = JSON.parse(errBody).detail || errBody.slice(0, 200); } catch { detail = errBody.slice(0, 200); }
      throw new Error(`NVIDIA API error ${response.status}: ${detail}`);
    }

    const data = await response.json();
    const finishReason = data.choices?.[0]?.finish_reason;
    let content = data.choices?.[0]?.message?.content || '';

    console.log('[PrivGuard] Nemotron finish_reason:', finishReason);
    console.log('[PrivGuard] Nemotron raw response length:', content.length);
    console.log('[PrivGuard] Nemotron raw response (first 500 chars):', content.slice(0, 500));

    if (finishReason === 'length') {
      console.warn('[PrivGuard] Nemotron response was truncated (max_tokens reached)');
    }

    // Nemotron Ultra wraps reasoning in <think>…</think>.
    // Handle both closed tags AND unclosed (truncated) think blocks.
    content = content.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
    // If <think> was never closed (truncated), strip everything from <think> onward
    content = content.replace(/<think>[\s\S]*/gi, '').trim();

    // Strip markdown code fences: ```json … ```
    content = content.replace(/```(?:json)?\s*/gi, '').replace(/```/g, '').trim();

    console.log('[PrivGuard] Nemotron cleaned content:', content.slice(0, 500));

    if (!content) {
      console.warn('[PrivGuard] Nemotron response was empty after stripping think blocks');
      return [];
    }

    // Extract JSON array from whatever remains
    const jsonMatch = content.match(/\[[\s\S]*\]/);
    if (!jsonMatch) {
      console.warn('[PrivGuard] No JSON array in Nemotron response:', content.slice(0, 500));
      return [];
    }

    try {
      const parsed = JSON.parse(jsonMatch[0]);
      console.log('[PrivGuard] Nemotron parsed findings:', parsed.length, parsed);
      return parsed;
    } catch (e) {
      console.warn('[PrivGuard] JSON parse error:', e.message, '| content:', jsonMatch[0].slice(0, 300));
      return [];
    }
  }

  /**
   * Merge Nemotron findings (which have boxes from matchFindingsToOcrBoxes)
   * with local regex findings, deduplicating by overlapping boxes/values.
   */
  function mergeFindings(nemotronFindings, localFindings) {
    const merged = [...nemotronFindings];
    for (const lf of localFindings) {
      // Check if any Nemotron finding already covers this value
      const isDuplicate = merged.some(nf => {
        if (!nf.value || !lf.value) return false;
        const nv = nf.value.replace(/[\s\-]/g, '').toLowerCase();
        const lv = lf.value.replace(/[\s\-]/g, '').toLowerCase();
        return nv.includes(lv) || lv.includes(nv);
      });
      if (!isDuplicate) merged.push(lf);
    }
    return merged;
  }

  /**
   * Match NVIDIA's text-based findings to OCR word bounding boxes.
   * Strategy:
   *   1. Exact substring match in OCR text (case-insensitive)
   *   2. Normalized match (strip spaces & dashes) — handles "4532 1234" vs "43321234"
   * Words whose positions overlap the matched range supply the blur boxes.
   */
  function matchFindingsToOcrBoxes(nvidiaFindings, ocrData) {
    return nvidiaFindings
      .filter(f => f && f.value)
      .map((f, idx) => {
        const value    = String(f.value).trim();
        const severity = ['CRITICAL','HIGH','MEDIUM','LOW'].includes(f.severity)
          ? f.severity : 'HIGH';
        const boxes = findTextBoxesInOcr(value, ocrData);
        console.log(`[PrivGuard] Matching "${value}" → ${boxes.length} boxes found`);
        return {
          id:         `nvidia_${idx}_${value.slice(0, 10).replace(/\s/g, '')}`,
          label:      f.label || 'Sensitive Data',
          severity,
          confidence: 0.95,
          value,
          boxes,
        };
      });
  }

  /**
   * Find a value string within the OCR data and return matching word boxes.
   * Returns [] if the value can't be located (e.g., OCR misread it).
   */
  function findTextBoxesInOcr(value, ocrData) {
    if (!value || !ocrData.text) return [];
    const fullText = ocrData.text;

    // ── Attempt 1: direct case-insensitive substring match ──
    const lcText  = fullText.toLowerCase();
    const lcValue = value.toLowerCase().trim();
    let idx = lcText.indexOf(lcValue);
    if (idx !== -1) {
      return getWordBoxesForRange(ocrData, idx, idx + lcValue.length);
    }

    // ── Attempt 2: normalized match (strip spaces, dashes, dots) ──
    // Build two parallel arrays: normalised chars and their original indices
    const origIndices = [];
    const normChars   = [];
    for (let i = 0; i < fullText.length; i++) {
      const c = fullText[i].toLowerCase();
      if (!/[\s\-.]/.test(c)) {
        origIndices.push(i);
        normChars.push(c);
      }
    }
    const compactText  = normChars.join('');
    const compactValue = lcValue.replace(/[\s\-.]/g, '');

    const ci = compactText.indexOf(compactValue);
    if (ci !== -1 && compactValue.length > 0) {
      const origStart = origIndices[ci];
      const origEnd   = origIndices[ci + compactValue.length - 1] + 1;
      return getWordBoxesForRange(ocrData, origStart, origEnd);
    }

    // Value not locatable in OCR output (OCR may have mis-read it)
    return [];
  }


  function detectSensitiveData(ocrData) {
    const fullText = ocrData.text || '';
    const findings = [];

    for (const p of PATTERNS) {
      const re = new RegExp(p.pattern.source, p.pattern.flags);
      let m;
      while ((m = re.exec(fullText)) !== null) {
        const matchStr = m[0];
        if (p.validate && !p.validate(matchStr)) continue;

        // Deduplicate
        const start = m.index;
        const end = start + matchStr.length;
        if (findings.some(f => f.start <= start && f.end >= end)) continue;

        // Map the text match back to OCR word bounding boxes
        const boxes = getWordBoxesForRange(ocrData, start, end);

        findings.push({
          id: p.id + '_' + start,
          label: p.label,
          severity: p.severity,
          confidence: p.confidence,
          value: matchStr,
          start,
          end,
          boxes,
        });

        if (matchStr.length === 0) re.lastIndex++;
      }
    }

    return findings;
  }

  /**
   * Given a character range [start, end) in the OCR full text,
   * return the bounding boxes of the words that overlap that range.
   */
  function getWordBoxesForRange(ocrData, start, end) {
    const boxes = [];
    let charIndex = 0;

    for (const line of ocrData.lines) {
      for (const word of line.words) {
        const wordStart = charIndex;
        const wordEnd = charIndex + word.text.length;

        // Check overlap
        if (wordEnd > start && wordStart < end) {
          boxes.push({
            x: word.bbox.x0,
            y: word.bbox.y0,
            w: word.bbox.x1 - word.bbox.x0,
            h: word.bbox.y1 - word.bbox.y0,
          });
        }

        charIndex = wordEnd + 1; // +1 for the space between words
      }
      // Lines in Tesseract output end with \n
      // The charIndex already advanced past the last word's space,
      // but the actual text has \n at line boundaries
    }

    return boxes;
  }

  /* ═══════════════════════════════════════════════════════════
     CANVAS BLURRING
     ═══════════════════════════════════════════════════════════ */

  function blurSensitiveRegions(canvas, img, findings) {
    const ctx = canvas.getContext('2d');
    const PAD = 8; // padding around each word box
    const BLUR_PASSES = 4; // stack multiple passes for an opaque blur

    for (const f of findings) {
      for (const box of f.boxes) {
        const x  = Math.max(0, box.x - PAD);
        const y  = Math.max(0, box.y - PAD);
        const bw = Math.min(canvas.width - x,  box.w + PAD * 2);
        const bh = Math.min(canvas.height - y, box.h + PAD * 2);

        // Stack multiple blur passes inside the clipped region.
        // Each pass redraws the already-blurred pixels, compounding the effect
        // until the content is fully unreadable.
        ctx.save();
        ctx.beginPath();
        ctx.roundRect(x, y, bw, bh, 4);
        ctx.clip();

        for (let i = 0; i < BLUR_PASSES; i++) {
          ctx.filter = 'blur(24px)';
          ctx.drawImage(canvas, 0, 0); // draw current canvas state (not original img)
        }

        ctx.filter = 'none';
        ctx.restore();
      }
    }
  }

  // kept to avoid reference errors — no longer used for rendering
  function getSeverityBorderColor(severity) {
    const map = {
      CRITICAL: 'rgba(214, 48, 49, 0.8)',
      HIGH:     'rgba(225, 112, 85, 0.7)',
      MEDIUM:   'rgba(253, 203, 110, 0.6)',
      LOW:      'rgba(0, 184, 148, 0.5)',
    };
    return map[severity] || map.MEDIUM;
  }

  /* ═══════════════════════════════════════════════════════════
     UI HELPERS
     ═══════════════════════════════════════════════════════════ */

  function showProgress() {
    uploadZone.hidden = true;
    resultsSection.hidden = true;
    progressSection.hidden = false;
  }

  function updateProgress(pct, label) {
    const offset = RING_CIRCUMFERENCE - (pct / 100) * RING_CIRCUMFERENCE;
    progressRing.style.strokeDashoffset = offset;
    progressPct.textContent = pct + '%';
    if (label) progressLabel.textContent = label;
  }

  function showResults(ocrData, findings) {
    progressSection.hidden = true;
    resultsSection.hidden = false;

    // Stats
    const totalWords = ocrData.words ? ocrData.words.length : countWords(ocrData);
    wordsScanned.textContent = totalWords;
    findingsCount.textContent = findings.length;

    // Risk level
    let rawScore = 0;
    for (const f of findings) rawScore += SEVERITY_WEIGHTS[f.severity] || 10;
    const score = Math.min(100, rawScore);
    const risk = score >= 80 ? 'CRITICAL' : score >= 55 ? 'HIGH' : score >= 30 ? 'MEDIUM' : score >= 1 ? 'LOW' : 'SAFE';

    riskLevelEl.textContent = risk;
    riskLevelEl.style.color = {
      CRITICAL: '#D63031', HIGH: '#E17055', MEDIUM: '#FDCB6E', LOW: '#00B894', SAFE: '#636e72'
    }[risk] || '#636e72';

    // Findings chips
    findingsPanel.innerHTML = '';
    if (findings.length === 0) {
      findingsPanel.innerHTML = `
        <div class="pg-no-findings">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <polyline points="9 12 11 14 15 10"/>
          </svg>
          <span>No sensitive data detected in this image.</span>
        </div>`;
    } else {
      for (const f of findings) {
        const chip = document.createElement('span');
        chip.className = 'pg-finding-chip';
        chip.dataset.severity = f.severity;
        chip.textContent = `${SEVERITY_ICONS[f.severity] || '⚪'} ${f.label}: ${truncate(f.value, 24)}`;
        findingsPanel.appendChild(chip);
      }
    }
  }

  function countWords(ocrData) {
    let count = 0;
    if (ocrData.lines) {
      for (const line of ocrData.lines) count += line.words.length;
    }
    return count;
  }

  function resetToUpload() {
    resultsSection.hidden = true;
    progressSection.hidden = true;
    uploadZone.hidden = false;
    fileInput.value = '';
    findingsPanel.innerHTML = '';
  }

  function truncate(str, max) {
    return str.length > max ? str.slice(0, max) + '…' : str;
  }

  /* ═══════════════════════════════════════════════════════════
     INIT
     ═══════════════════════════════════════════════════════════ */
  loadSettings();

})();
