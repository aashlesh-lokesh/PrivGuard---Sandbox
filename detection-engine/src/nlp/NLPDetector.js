/**
 * NLP Detector
 * Uses compromise.js for context-aware sensitive data detection:
 *  - Physical addresses
 *  - Person names (in sensitive contexts)
 *  - Organization names
 *  - Confidential phrase detection
 *  - OTP-like numeric codes in context
 */

import nlp from 'compromise';
import privguardPlugin from './customPlugin.js';

// Register the PrivGuard plugin once at module load
nlp.plugin(privguardPlugin);

// ---------------------------------------------------------------------------
// Address heuristic patterns (compromise handles NER; we add postal patterns)
// ---------------------------------------------------------------------------
const ADDRESS_PATTERN =
  /\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,4}(?:St(?:reet)?|Ave(?:nue)?|Rd|Road|Blvd|Boulevard|Dr(?:ive)?|Ln|Lane|Ct|Court|Pl|Place|Way|Terr(?:ace)?|Cir(?:cle)?|Hwy|Highway)[\.,]?\s*(?:[A-Za-z\s]+,\s*)?(?:[A-Z]{2}\s+)?\d{5}(?:-\d{4})?\b/gi;

const POSTAL_CODE_IN_ADDRESS =
  /\b(?:[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}|\d{5}(?:-\d{4})?)\b/g;

// ---------------------------------------------------------------------------
// Sensitive phrase patterns (documents, medical, legal, etc.)
// ---------------------------------------------------------------------------
const SENSITIVE_PHRASES = [
  { re: /\b(?:do not share|not for distribution|strictly confidential|for your eyes only|internal[\s\-]only|company[\s\-]confidential)\b/gi, type: 'SENSITIVE_PHRASE', label: 'Confidential Phrase' },
  { re: /\b(?:medical[\s\-]?record|patient[\s\-]?id|diagnosis|prescription|ssn|social[\s\-]security)\b/gi, type: 'SENSITIVE_CONTEXT', label: 'Medically Sensitive Context' },
];

// ---------------------------------------------------------------------------
// Main detector class
// ---------------------------------------------------------------------------
export class NLPDetector {
  /**
   * Analyse text and return NLP-based findings.
   *
   * @param {string} text - Input text to analyse.
   * @param {object} [options]
   * @param {boolean} [options.detectNames=true]
   * @param {boolean} [options.detectAddresses=true]
   * @param {boolean} [options.detectOrgs=false]  Organisation names are lower risk; off by default.
   * @returns {import('../DetectionEngine.js').Finding[]}
   */
  analyze(text, options = {}) {
    const {
      detectNames = true,
      detectAddresses = true,
      detectOrgs = false,
    } = options;

    if (!text || typeof text !== 'string') return [];

    const findings = [];
    const doc = nlp(text);

    // ------------------------------------------------------------------
    // 1. Full physical addresses (regex-based, positional)
    // ------------------------------------------------------------------
    if (detectAddresses) {
      const addrRe = new RegExp(ADDRESS_PATTERN.source, 'gi');
      let m;
      while ((m = addrRe.exec(text)) !== null) {
        findings.push(this._makeFinding({
          type: 'ADDRESS',
          label: 'Physical Address',
          category: 'location',
          severity: 'MEDIUM',
          confidence: 0.80,
          value: m[0],
          position: { start: m.index, end: m.index + m[0].length },
          redacted: '[ADDRESS REDACTED]',
        }));
      }
    }

    // ------------------------------------------------------------------
    // 2. Person names (compromise NER)
    // ------------------------------------------------------------------
    if (detectNames) {
      const people = doc.people().json();
      for (const person of people) {
        const name = person.text;
        if (!name || name.trim().length < 3) continue;

        // Locate first occurrence in the original text
        const idx = text.indexOf(name);
        if (idx === -1) continue;

        findings.push(this._makeFinding({
          type: 'PERSON_NAME',
          label: 'Person Name',
          category: 'personal',
          severity: 'LOW',
          confidence: 0.70,
          value: name,
          position: { start: idx, end: idx + name.length },
          redacted: this._initials(name),
        }));
      }
    }

    // ------------------------------------------------------------------
    // 3. Organisation names (compromise NER)
    // ------------------------------------------------------------------
    if (detectOrgs) {
      const orgs = doc.organizations().json();
      for (const org of orgs) {
        const orgName = org.text;
        if (!orgName || orgName.trim().length < 2) continue;
        const idx = text.indexOf(orgName);
        if (idx === -1) continue;

        findings.push(this._makeFinding({
          type: 'ORGANIZATION',
          label: 'Organization Name',
          category: 'personal',
          severity: 'LOW',
          confidence: 0.65,
          value: orgName,
          position: { start: idx, end: idx + orgName.length },
          redacted: `[ORG: ${orgName[0]}***]`,
        }));
      }
    }

    // ------------------------------------------------------------------
    // 4. Sensitive phrases
    // ------------------------------------------------------------------
    for (const sp of SENSITIVE_PHRASES) {
      const re = new RegExp(sp.re.source, 'gi');
      let m;
      while ((m = re.exec(text)) !== null) {
        findings.push(this._makeFinding({
          type: sp.type,
          label: sp.label,
          category: 'context',
          severity: 'MEDIUM',
          confidence: 0.88,
          value: m[0],
          position: { start: m.index, end: m.index + m[0].length },
          redacted: '[SENSITIVE CONTENT]',
        }));
      }
    }

    // ------------------------------------------------------------------
    // 5. Places (compromise NER) – for partial address detection
    // ------------------------------------------------------------------
    if (detectAddresses) {
      const places = doc.places().json();
      for (const place of places) {
        const placeName = place.text;
        if (!placeName || placeName.trim().length < 3) continue;

        // Only flag if it looks like a street address fragment (has digits)
        if (!/\d/.test(placeName)) continue;

        const idx = text.indexOf(placeName);
        if (idx === -1) continue;

        // Skip if already covered by a full-address finding
        const alreadyCovered = findings.some(
          (f) => f.type === 'ADDRESS' && f.position.start <= idx && f.position.end >= idx + placeName.length,
        );
        if (alreadyCovered) continue;

        findings.push(this._makeFinding({
          type: 'ADDRESS',
          label: 'Location / Address Fragment',
          category: 'location',
          severity: 'LOW',
          confidence: 0.60,
          value: placeName,
          position: { start: idx, end: idx + placeName.length },
          redacted: '[LOCATION REDACTED]',
        }));
      }
    }

    return findings;
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  _makeFinding(props) {
    return {
      id: `nlp_${props.type}_${props.position.start}`,
      source: 'nlp',
      ...props,
    };
  }

  _initials(name) {
    return name
      .split(/\s+/)
      .map((w) => w[0] + '.')
      .join(' ') + ' [NAME REDACTED]';
  }
}

export default NLPDetector;
