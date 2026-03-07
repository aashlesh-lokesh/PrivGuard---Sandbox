/**
 * Contact Information Pattern Definitions
 * Detects: Phone Numbers, Email Addresses
 */

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------
export const CONTACT_PATTERNS = [
  // ---- Phone Numbers ------------------------------------------------------
  {
    id: 'PHONE_E164',
    type: 'PHONE_NUMBER',
    label: 'International Phone Number (E.164)',
    category: 'contact',
    severity: 'MEDIUM',
    confidence: 0.90,
    // E.164: +1-15 digits, total 7-15 digits after country code
    pattern: /(?<!\d)\+[1-9]\d{6,14}(?!\d)/g,
    validate: (m) => {
      const digits = m.replace(/\D/g, '');
      return digits.length >= 7 && digits.length <= 15;
    },
    redact: (raw) => {
      // Keep country code + last 4
      const cc = raw.match(/^\+\d{1,3}/)?.[0] || '+X';
      const last4 = raw.replace(/\D/g, '').slice(-4);
      return `${cc}-***-***-${last4}`;
    },
  },
  {
    id: 'PHONE_US',
    type: 'PHONE_NUMBER',
    label: 'US/Canada Phone Number',
    category: 'contact',
    severity: 'MEDIUM',
    confidence: 0.85,
    // North American format: (NXX) NXX-XXXX, NXX-NXX-XXXX, NXX.NXX.XXXX
    pattern: /\b(?:\+?1[\s.\-]?)?\(?(?:[2-9][0-8][0-9])\)?[\s.\-]?(?:[2-9][0-9]{2})[\s.\-]?(?:[0-9]{4})\b/g,
    validate: (m) => {
      const digits = m.replace(/\D/g, '');
      const core = digits.startsWith('1') && digits.length === 11 ? digits.slice(1) : digits;
      // Reject obvious test numbers like 555-0100 through 555-0199
      return core.length === 10 && !(core.startsWith('555') && core[3] === '0');
    },
    redact: (raw) => {
      const d = raw.replace(/\D/g, '');
      const last4 = d.slice(-4);
      return `(***) ***-${last4}`;
    },
  },
  {
    id: 'PHONE_UK',
    type: 'PHONE_NUMBER',
    label: 'UK Phone Number',
    category: 'contact',
    severity: 'MEDIUM',
    confidence: 0.82,
    // UK: 01, 02, 03, 07, 08 formats – 10-11 digits
    pattern: /\b(?:0|\+44[\s\-]?)(?:1\d[\s\-]?\d{4}|2\d[\s\-]?\d{4}|3\d{2}[\s\-]?\d{3}|7\d{3}[\s\-]?\d{6}|8\d{2}[\s\-]?\d{3})[\s\-]?\d{4}\b/g,
    redact: (raw) => {
      const d = raw.replace(/\D/g, '');
      return d.slice(0, 3) + ' *** ' + d.slice(-4);
    },
  },
  {
    id: 'PHONE_GENERIC',
    type: 'PHONE_NUMBER',
    label: 'Phone Number',
    category: 'contact',
    severity: 'MEDIUM',
    confidence: 0.65,
    // Generic: digits with separators, 7-15 digits total, with context keyword
    pattern: /\b(?:phone|tel(?:ephone)?|mobile|cell|fax|contact)[\s:._\-#]*(\+?[\d][\d\s.\-()]{5,18}[\d])\b/gi,
    captureGroup: 1,
    validate: (m) => {
      const digits = m.replace(/\D/g, '');
      return digits.length >= 7 && digits.length <= 15;
    },
    redact: (raw) => {
      const d = raw.replace(/\D/g, '');
      return d.slice(0, 2) + '***' + d.slice(-4);
    },
  },

  // ---- Email Addresses ----------------------------------------------------
  {
    id: 'EMAIL_ADDRESS',
    type: 'EMAIL',
    label: 'Email Address',
    category: 'contact',
    severity: 'LOW',
    confidence: 0.95,
    // RFC 5321 simplified: local@domain.tld
    pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b/g,
    validate: (m) => {
      // Reject common placeholder emails
      const lower = m.toLowerCase();
      return !['example.com', 'test.com', 'domain.com', 'email.com',
               'youremail.com'].some(d => lower.endsWith(d));
    },
    redact: (raw) => {
      const [local, domain] = raw.split('@');
      const redactedLocal = local[0] + '***' + (local.length > 1 ? local.slice(-1) : '');
      return `${redactedLocal}@${domain}`;
    },
  },
];
