/**
 * OCR Processor
 * Wraps Tesseract.js v5 for client-side image-to-text extraction.
 * All processing happens locally in the browser – no data leaves the device.
 *
 * Usage:
 *   const ocr = new OCRProcessor();
 *   await ocr.init('eng');
 *   const { text, confidence } = await ocr.extractText(imageSource);
 *   await ocr.terminate();
 */

import { createWorker } from 'tesseract.js';

// ---------------------------------------------------------------------------
// Image pre-processing helpers (canvas-based, browser environment)
// ---------------------------------------------------------------------------

/**
 * Pre-process an image element or blob to improve OCR accuracy:
 *  - Converts to greyscale
 *  - Applies contrast enhancement
 *  - Returns a canvas ImageData URL
 *
 * @param {HTMLImageElement|HTMLCanvasElement|Blob|string} source
 * @returns {Promise<string>} data URL of the pre-processed image
 */
async function preprocessImage(source) {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');

  const img = await loadImageSource(source);
  canvas.width = img.naturalWidth || img.width;
  canvas.height = img.naturalHeight || img.height;

  // Draw original
  ctx.drawImage(img, 0, 0);

  // Apply greyscale + contrast boost via CSS filter
  ctx.filter = 'grayscale(100%) contrast(150%)';
  ctx.drawImage(img, 0, 0);

  return canvas.toDataURL('image/png');
}

/**
 * Resolves any image source into an HTMLImageElement.
 */
function loadImageSource(source) {
  return new Promise((resolve, reject) => {
    if (source instanceof HTMLImageElement) return resolve(source);
    if (source instanceof HTMLCanvasElement) {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = reject;
      img.src = source.toDataURL();
      return;
    }

    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = reject;

    if (source instanceof Blob) {
      img.src = URL.createObjectURL(source);
    } else if (typeof source === 'string') {
      // Either a data URL or an object URL
      img.src = source;
    } else {
      reject(new Error(`Unsupported image source type: ${typeof source}`));
    }
  });
}

// ---------------------------------------------------------------------------
// OCRProcessor class
// ---------------------------------------------------------------------------

export class OCRProcessor {
  constructor() {
    /** @type {import('tesseract.js').Worker|null} */
    this._worker = null;
    this._initializedLangs = new Set();
    this._isReady = false;
  }

  /**
   * Initialise the Tesseract worker and load the specified language data.
   * Call once before using `extractText`.
   *
   * @param {string|string[]} [langs='eng'] - Language code(s) e.g. 'eng', ['eng','spa']
   */
  async init(langs = 'eng') {
    const langStr = Array.isArray(langs) ? langs.join('+') : langs;

    // Reuse existing worker if already ready with the same languages
    if (this._isReady && this._initializedLangs.has(langStr)) return;

    if (this._worker) await this.terminate();

    this._worker = await createWorker(langStr, 1, {
      // Disable Tesseract console output in production
      logger: () => {},
      errorHandler: (err) => console.error('[OCRProcessor] Tesseract error:', err),
    });

    // Optimise OCR for screenshots / web forms – treat input as uniform text blocks
    await this._worker.setParameters({
      tessedit_pageseg_mode: '3',   // PSM_AUTO – fully automatic page segmentation
      preserve_interword_spaces: '1',
    });

    this._initializedLangs.add(langStr);
    this._isReady = true;
  }

  /**
   * Extract text from an image source.
   *
   * @param {HTMLImageElement|HTMLCanvasElement|Blob|string} imageSource
   * @param {object} [options]
   * @param {boolean} [options.preprocess=true] - Apply greyscale+contrast preprocessing
   * @param {string|string[]} [options.langs='eng'] - Override language for this request
   * @returns {Promise<OCRResult>}
   */
  async extractText(imageSource, options = {}) {
    const { preprocess = true, langs } = options;

    if (!this._isReady) {
      await this.init(langs);
    } else if (langs) {
      await this.init(langs);
    }

    let source = imageSource;
    if (preprocess && typeof document !== 'undefined') {
      try {
        source = await preprocessImage(imageSource);
      } catch {
        // Fall back to raw source if preprocessing fails (e.g., CORS)
        source = imageSource;
      }
    }

    const { data } = await this._worker.recognize(source);

    return {
      text: data.text.trim(),
      confidence: data.confidence,   // 0-100 (Tesseract's own confidence score)
      words: data.words.map((w) => ({
        text: w.text,
        confidence: w.confidence,
        bbox: w.bbox,               // { x0, y0, x1, y1 } for highlight overlays
      })),
      lines: data.lines.map((l) => ({
        text: l.text,
        confidence: l.confidence,
        bbox: l.bbox,
      })),
    };
  }

  /**
   * Terminate the Tesseract worker and release memory.
   * Call when the OCRProcessor is no longer needed.
   */
  async terminate() {
    if (this._worker) {
      await this._worker.terminate();
      this._worker = null;
      this._isReady = false;
      this._initializedLangs.clear();
    }
  }

  get isReady() {
    return this._isReady;
  }
}

/**
 * @typedef {object} OCRResult
 * @property {string} text - Full extracted text
 * @property {number} confidence - Overall confidence (0-100)
 * @property {Array<{text:string, confidence:number, bbox:object}>} words
 * @property {Array<{text:string, confidence:number, bbox:object}>} lines
 */

export default OCRProcessor;
