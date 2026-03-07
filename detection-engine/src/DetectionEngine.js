/**
 * DetectionEngine – Main Orchestrator
 *
 * Combines the Regex Engine, NLP Detector, OCR Processor, and Privacy Scorer
 * into a single async API that the browser extension content script can call.
 *
 * All processing is done locally. No data is sent to any external server.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Quick start
 * ─────────────────────────────────────────────────────────────────────────────
 *   import DetectionEngine from './DetectionEngine.js';
 *
 *   const engine = new DetectionEngine();
 *
 *   // Scan a text string
 *   const result = await engine.analyzeText('My SSN is 123-45-6789');
 *   console.log(result.score, result.riskLevel); // 55, 'HIGH'
 *
 *   // Scan an image (Blob, HTMLImageElement, data URL, or Object URL)
 *   const imageResult = await engine.analyzeImage(blob);
 *
 *   // Combined scan (text already extracted from a form field + an attached image)
 *   const combined = await engine.analyze({ text: '...', image: blob });
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { runRegexPatterns } from './patterns/index.js';
import { NLPDetector } from './nlp/NLPDetector.js';
import { OCRProcessor } from './ocr/OCRProcessor.js';
import { PrivacyScorer } from './scoring/PrivacyScorer.js';

export class DetectionEngine {
  /**
   * @param {object} [options]
   * @param {boolean} [options.enableNLP=true]      - Use compromise.js for context detection
   * @param {boolean} [options.enableOCR=false]     - Enable OCR (lazy-initialiased on first use)
   * @param {string|string[]} [options.ocrLangs='eng'] - Tesseract language codes
   * @param {boolean} [options.detectNames=true]    - NLP: detect person names
   * @param {boolean} [options.detectAddresses=true]- NLP: detect physical addresses
   */
  constructor(options = {}) {
    const {
      enableNLP = true,
      enableOCR = false,
      ocrLangs = 'eng',
      detectNames = true,
      detectAddresses = true,
    } = options;

    this._nlpOptions = { detectNames, detectAddresses };
    this._enableNLP = enableNLP;
    this._enableOCR = enableOCR;
    this._ocrLangs = ocrLangs;

    this._nlp = enableNLP ? new NLPDetector() : null;
    this._ocr = null;  // lazy-initialised
    this._scorer = new PrivacyScorer();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public API
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Analyse plain text for sensitive data.
   *
   * @param {string} text
   * @returns {Promise<DetectionResult>}
   */
  async analyzeText(text) {
    return this.analyze({ text });
  }

  /**
   * Analyse an image by first extracting text via OCR, then running
   * the full detection pipeline on the extracted text.
   *
   * @param {HTMLImageElement|HTMLCanvasElement|Blob|string} imageSource
   * @returns {Promise<DetectionResult>}
   */
  async analyzeImage(imageSource) {
    return this.analyze({ image: imageSource });
  }

  /**
   * Full analysis: accepts text, an image, or both.
   * Text is analysed directly; images are first processed with OCR.
   *
   * @param {object} input
   * @param {string}  [input.text]  - Plain text to scan
   * @param {*}       [input.image] - Image source (Blob, HTMLImageElement, data URL, etc.)
   * @returns {Promise<DetectionResult>}
   */
  async analyze(input = {}) {
    const { text, image } = input;
    let combinedText = (text ?? '').trim();
    let ocrMeta = null;

    // ------------------------------------------------------------------
    // 1. OCR: extract text from image (if provided)
    // ------------------------------------------------------------------
    if (image) {
      const ocr = await this._getOCR();
      if (ocr) {
        const ocrResult = await ocr.extractText(image, { langs: this._ocrLangs });
        if (ocrResult.text) {
          ocrMeta = {
            confidence: ocrResult.confidence,
            wordCount: ocrResult.words.length,
          };
          // Append OCR text with a separator so positions don't mix with raw text positions
          combinedText = combinedText
            ? `${combinedText}\n\n${ocrResult.text}`
            : ocrResult.text;
        }
      }
    }

    if (!combinedText) {
      return this._emptyResult();
    }

    // ------------------------------------------------------------------
    // 2. Regex engine
    // ------------------------------------------------------------------
    const regexFindings = runRegexPatterns(combinedText);

    // ------------------------------------------------------------------
    // 3. NLP engine
    // ------------------------------------------------------------------
    let nlpFindings = [];
    if (this._enableNLP && this._nlp) {
      nlpFindings = this._nlp.analyze(combinedText, this._nlpOptions);
    }

    // ------------------------------------------------------------------
    // 4. Merge & deduplicate findings
    // ------------------------------------------------------------------
    const allFindings = this._mergeFindings(regexFindings, nlpFindings);

    // ------------------------------------------------------------------
    // 5. Score
    // ------------------------------------------------------------------
    const scoreResult = this._scorer.score(allFindings);

    // ------------------------------------------------------------------
    // 6. Build final result
    // ------------------------------------------------------------------
    return {
      ...scoreResult,
      findings: allFindings,
      meta: {
        textLength: combinedText.length,
        ocrUsed: !!ocrMeta,
        ocrMeta,
        regexFindingsCount: regexFindings.length,
        nlpFindingsCount: nlpFindings.length,
        analysedAt: new Date().toISOString(),
      },

      /**
       * Returns the input text with all detected sensitive values replaced by
       * their redacted equivalents.
       *
       * @returns {string}
       */
      redactedText: () => this._buildRedactedText(combinedText, allFindings),
    };
  }

  /**
   * Release the OCR worker when the engine is no longer needed.
   * The extension should call this when the user navigates away.
   */
  async destroy() {
    if (this._ocr) {
      await this._ocr.terminate();
      this._ocr = null;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private helpers
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Lazy-initialise the OCR processor on first use.
   * Returns null if OCR is disabled.
   */
  async _getOCR() {
    if (!this._enableOCR) return null;
    if (!this._ocr) {
      this._ocr = new OCRProcessor();
      await this._ocr.init(this._ocrLangs);
    }
    return this._ocr;
  }

  /**
   * Merge regex and NLP findings, removing positional overlaps.
   * Regex findings take precedence over NLP when they overlap.
   */
  _mergeFindings(regexFindings, nlpFindings) {
    const merged = [...regexFindings];

    for (const nlpFinding of nlpFindings) {
      const overlaps = merged.some(
        (rf) =>
          rf.position.start < nlpFinding.position.end &&
          rf.position.end > nlpFinding.position.start,
      );
      if (!overlaps) {
        merged.push(nlpFinding);
      }
    }

    // Sort by position for easy UI rendering
    return merged.sort((a, b) => a.position.start - b.position.start);
  }

  /**
   * Build a version of the text with sensitive values replaced.
   * Works backwards through findings by position to preserve offsets.
   */
  _buildRedactedText(text, findings) {
    // Sort descending by start position so replacements don't shift later indices
    const sorted = [...findings].sort((a, b) => b.position.start - a.position.start);
    let result = text;
    for (const f of sorted) {
      const before = result.slice(0, f.position.start);
      const after = result.slice(f.position.end);
      result = before + (f.redacted ?? '[REDACTED]') + after;
    }
    return result;
  }

  _emptyResult() {
    const scoreResult = this._scorer.score([]);
    return {
      ...scoreResult,
      findings: [],
      meta: {
        textLength: 0,
        ocrUsed: false,
        ocrMeta: null,
        regexFindingsCount: 0,
        nlpFindingsCount: 0,
        analysedAt: new Date().toISOString(),
      },
      redactedText: () => '',
    };
  }
}

/**
 * @typedef {object} Finding
 * @property {string}   id          - Unique finding ID (patternId_position)
 * @property {string}   type        - Data type key (e.g. 'CREDIT_CARD', 'SSN')
 * @property {string}   patternId   - ID of the specific pattern that matched
 * @property {string}   label       - Human-readable label
 * @property {string}   category    - 'financial' | 'identity' | 'credentials' | 'contact' | 'location' | 'network' | 'personal' | 'context'
 * @property {string}   severity    - 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
 * @property {number}   confidence  - Confidence 0.0–1.0
 * @property {string}   value       - The matched/captured value
 * @property {string}   rawMatch    - Full regex match (may differ from value if capture group used)
 * @property {string}   redacted    - Safe redacted representation for display
 * @property {{start:number, end:number}} position - Character positions in input text
 * @property {'regex'|'nlp'|'ocr'} source - Which engine found it
 */

/**
 * @typedef {import('./scoring/PrivacyScorer.js').ScoreResult & {
 *   findings: Finding[],
 *   meta: object,
 *   redactedText: () => string
 * }} DetectionResult
 */

export default DetectionEngine;
