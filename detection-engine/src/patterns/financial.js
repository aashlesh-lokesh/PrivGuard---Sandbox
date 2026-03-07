/**
 * Financial Pattern Definitions
 * Detects: Credit/Debit Cards, CVV, Expiry Dates, IBAN, Bank Accounts, Routing Numbers
 */

// ---------------------------------------------------------------------------
// Luhn algorithm – used to validate card numbers and reduce false positives
// ---------------------------------------------------------------------------
export function luhnCheck(numStr) {
  const digits = numStr.replace(/[\s\-]/g, '');
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

// ---------------------------------------------------------------------------
// ABA routing number check digit validation
// ---------------------------------------------------------------------------
function abaCheck(numStr) {
  const d = numStr.replace(/\D/g, '').split('').map(Number);
  if (d.length !== 9) return false;
  const checksum = (
    3 * (d[0] + d[3] + d[6]) +
    7 * (d[1] + d[4] + d[7]) +
    1 * (d[2] + d[5] + d[8])
  ) % 10;
  return checksum === 0;
}

// ---------------------------------------------------------------------------
// Redaction helpers
// ---------------------------------------------------------------------------
function redactCard(raw) {
  const digits = raw.replace(/[\s\-]/g, '');
  const first4 = digits.slice(0, 4);
  const last4 = digits.slice(-4);
  return `${first4} **** **** ${last4}`;
}

function redactIban(raw) {
  return raw.slice(0, 4) + ' **** **** ' + raw.slice(-4);
}

// ---------------------------------------------------------------------------
// Pattern definitions
// Each entry: { id, type, label, category, severity, pattern (RegExp with /g),
//               validate? (fn), redact (fn), confidence }
// ---------------------------------------------------------------------------
export const FINANCIAL_PATTERNS = [
  // ---- Credit / Debit Cards -----------------------------------------------
  {
    id: 'CREDIT_CARD_VISA',
    type: 'CREDIT_CARD',
    label: 'Visa Card Number',
    category: 'financial',
    severity: 'HIGH',
    confidence: 0.95,
    // 16-digit Visa (formatted or unformatted)
    pattern: /\b4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/g,
    validate: (m) => luhnCheck(m),
    redact: redactCard,
  },
  {
    id: 'CREDIT_CARD_MASTERCARD',
    type: 'CREDIT_CARD',
    label: 'Mastercard Number',
    category: 'financial',
    severity: 'HIGH',
    confidence: 0.95,
    // Mastercard: 51-55 or 2221-2720 (prefix fills 4 digits, then 3 more groups of 4)
    pattern: /\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/g,
    validate: (m) => luhnCheck(m),
    redact: redactCard,
  },
  {
    id: 'CREDIT_CARD_AMEX',
    type: 'CREDIT_CARD',
    label: 'American Express Card Number',
    category: 'financial',
    severity: 'HIGH',
    confidence: 0.95,
    // Amex: 15 digits, starts with 34 or 37
    pattern: /\b3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}\b/g,
    validate: (m) => luhnCheck(m),
    redact: (raw) => {
      const d = raw.replace(/[\s\-]/g, '');
      return `${d.slice(0, 4)} ****** ${d.slice(-5)}`;
    },
  },
  {
    id: 'CREDIT_CARD_DISCOVER',
    type: 'CREDIT_CARD',
    label: 'Discover Card Number',
    category: 'financial',
    severity: 'HIGH',
    confidence: 0.95,
    // Discover: 6011, 622126-622925, 644-649, 65
    pattern: /\b6(?:011|5[0-9]{2})[0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/g,
    validate: (m) => luhnCheck(m),
    redact: redactCard,
  },
  {
    id: 'CREDIT_CARD_JCB',
    type: 'CREDIT_CARD',
    label: 'JCB Card Number',
    category: 'financial',
    severity: 'HIGH',
    confidence: 0.90,
    // JCB: 3528-3589, 16 digits
    pattern: /\b35(?:2[89]|[3-8][0-9])[0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/g,
    validate: (m) => luhnCheck(m),
    redact: redactCard,
  },

  // ---- CVV / CVC ----------------------------------------------------------
  {
    id: 'CVV_CODE',
    type: 'CVV',
    label: 'CVV / Security Code',
    category: 'financial',
    severity: 'HIGH',
    confidence: 0.85,
    // Must appear near the keyword to avoid matching random 3-4 digit numbers
    pattern: /\b(?:cvv2?|cvc2?|cid|security[\s_-]?code|card[\s_-]?verif\w+)[\s:=]*([0-9]{3,4})\b/gi,
    captureGroup: 1,
    redact: () => '[CVV REDACTED]',
  },

  // ---- Card Expiry Date ---------------------------------------------------
  {
    id: 'CARD_EXPIRY',
    type: 'CARD_EXPIRY',
    label: 'Card Expiry Date',
    category: 'financial',
    severity: 'MEDIUM',
    confidence: 0.75,
    // MM/YY or MM/YYYY optionally with expiry/exp/expiration keyword context
    pattern: /\b(?:exp(?:iry|iration)?[\s:=]*)?(?:0[1-9]|1[0-2])[\s\/\-](?:2[0-9]|20[2-9][0-9])\b/gi,
    redact: () => '[EXPIRY REDACTED]',
  },

  // ---- IBAN ---------------------------------------------------------------
  {
    id: 'IBAN',
    type: 'IBAN',
    label: 'International Bank Account Number (IBAN)',
    category: 'financial',
    severity: 'HIGH',
    confidence: 0.92,
    // IBAN: CC + 2-digit check + up to 30 alphanumeric (no lowercase)
    pattern: /\b[A-Z]{2}[0-9]{2}[\s]?(?:[A-Z0-9]{4}[\s]?){1,7}[A-Z0-9]{1,4}\b/g,
    validate: (m) => {
      const raw = m.replace(/\s/g, '');
      // IBAN length check per country would be ideal; accept 15-34 chars
      return raw.length >= 15 && raw.length <= 34;
    },
    redact: redactIban,
  },

  // ---- US Bank Account ----------------------------------------------------
  {
    id: 'BANK_ACCOUNT_US',
    type: 'BANK_ACCOUNT',
    label: 'US Bank Account Number',
    category: 'financial',
    severity: 'HIGH',
    confidence: 0.70,
    // 8-17 digit account number, require context keyword to reduce FP
    pattern: /\b(?:account[\s_-]?(?:no|number|#)?|acct[\s#.:]*)[:\s#.]*([0-9]{8,17})\b/gi,
    captureGroup: 1,
    redact: (raw) => raw.slice(0, 2) + '***** ' + raw.slice(-4),
  },

  // ---- ABA Routing Number -------------------------------------------------
  {
    id: 'ROUTING_NUMBER',
    type: 'ROUTING_NUMBER',
    label: 'ABA Routing Number',
    category: 'financial',
    severity: 'MEDIUM',
    confidence: 0.80,
    // 9-digit ABA routing with optional context keyword
    pattern: /\b(?:routing[\s_-]?(?:no|number|#|transit)?[\s:#.]*)?([0-9]{9})\b/g,
    validate: (m) => {
      const digits = m.replace(/\D/g, '');
      return digits.length === 9 && abaCheck(digits);
    },
    captureGroup: 1,
    redact: (raw) => `****${raw.slice(-4)}`,
  },
];
