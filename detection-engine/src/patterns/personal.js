/**
 * Personal Identifier Pattern Definitions
 * Detects: SSN, Passports, National IDs, Driver's Licenses, Date of Birth
 */

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------
export const PERSONAL_PATTERNS = [
  // ---- US Social Security Number -----------------------------------------
  {
    id: 'US_SSN',
    type: 'SSN',
    label: 'US Social Security Number',
    category: 'identity',
    severity: 'CRITICAL',
    confidence: 0.92,
    // Excludes invalid area numbers: 000, 666, 900-999
    // Excludes invalid group numbers: 00
    // Excludes invalid serial numbers: 0000
    pattern: /\b(?!000|666|9\d{2})\d{3}[\s\-]?(?!00)\d{2}[\s\-]?(?!0000)\d{4}\b/g,
    validate: (m) => {
      // Reject obvious sequential patterns (111-11-1111, 123-45-6789)
      const digits = m.replace(/[\s\-]/g, '');
      return !['123456789', '111111111', '222222222', '333333333',
               '444444444', '555555555', '666666666', '777777777',
               '888888888', '999999999'].includes(digits);
    },
    redact: (raw) => {
      const d = raw.replace(/[\s\-]/g, '');
      return `***-**-${d.slice(-4)}`;
    },
  },

  // ---- UK National Insurance Number --------------------------------------
  {
    id: 'UK_NINO',
    type: 'NATIONAL_ID',
    label: 'UK National Insurance Number',
    category: 'identity',
    severity: 'CRITICAL',
    confidence: 0.95,
    // Format: XX 99 99 99 X  (two letters, six digits, one letter)
    // Certain letters are disallowed in specific positions
    pattern: /\b(?![DFIQUV])[A-Z](?![DFIQUVO])[A-Z][\s]?\d{2}[\s]?\d{2}[\s]?\d{2}[\s]?[A-D]\b/gi,
    redact: (raw) => raw.slice(0, 2) + '** ** **' + raw.slice(-2),
  },

  // ---- Canadian SIN -------------------------------------------------------
  {
    id: 'CANADIAN_SIN',
    type: 'SSN',
    label: 'Canadian Social Insurance Number',
    category: 'identity',
    severity: 'CRITICAL',
    confidence: 0.80,
    // 9 digits, often formatted as NNN-NNN-NNN
    pattern: /\b(?:sin|social[\s_\-]?insurance[\s_\-]?(?:number|no|#)?[\s:]*)?([0-9]{3})[\s\-]([0-9]{3})[\s\-]([0-9]{3})\b/gi,
    validate: (m) => {
      // Luhn check applies to Canadian SINs
      const digits = m.replace(/[\s\-]/g, '');
      if (digits.length !== 9) return false;
      let sum = 0;
      let alt = false;
      for (let i = digits.length - 1; i >= 0; i--) {
        let d = parseInt(digits[i], 10);
        if (alt) {
          d *= 2;
          if (d > 9) d -= 9;
        }
        sum += d;
        alt = !alt;
      }
      return sum % 10 === 0;
    },
    redact: (raw) => {
      const d = raw.replace(/[\s\-]/g, '');
      return `***-***-${d.slice(-3)}`;
    },
  },

  // ---- Passport Numbers ---------------------------------------------------
  {
    id: 'US_PASSPORT',
    type: 'PASSPORT',
    label: 'US Passport Number',
    category: 'identity',
    severity: 'HIGH',
    confidence: 0.80,
    // US passport: letter + 8 digits OR 9 digits (with context)
    pattern: /\b(?:passport[\s_\-]?(?:no|number|#)?[\s:.]*)?([A-Z][0-9]{8}|[0-9]{9})\b/gi,
    captureGroup: 1,
    redact: (raw) => raw.slice(0, 2) + '*****' + raw.slice(-2),
  },
  {
    id: 'GENERIC_PASSPORT',
    type: 'PASSPORT',
    label: 'Passport Number',
    category: 'identity',
    severity: 'HIGH',
    confidence: 0.70,
    // Generic: keyword + 8-9 alphanumeric chars
    pattern: /\bpassport[\s_\-]?(?:no|number|#)?[\s:.]*([A-Z0-9]{8,10})\b/gi,
    captureGroup: 1,
    redact: (raw) => raw.slice(0, 2) + '*****' + raw.slice(-2),
  },

  // ---- Driver's License --------------------------------------------------
  {
    id: 'DRIVERS_LICENSE',
    type: 'DRIVERS_LICENSE',
    label: "Driver's License Number",
    category: 'identity',
    severity: 'HIGH',
    confidence: 0.75,
    // Keyword required to reduce false positives; 6-15 alphanumeric
    pattern: /\b(?:driver[s']?[\s_\-]?(?:license|licence|lic)|DL[\s#:.])[\s#:.]?([A-Z][0-9]{3,7}[A-Z0-9]{0,8}|[0-9]{6,15})\b/gi,
    captureGroup: 1,
    redact: (raw) => raw.slice(0, 2) + '****' + raw.slice(-2),
  },

  // ---- Date of Birth ------------------------------------------------------
  {
    id: 'DATE_OF_BIRTH',
    type: 'DATE_OF_BIRTH',
    label: 'Date of Birth',
    category: 'identity',
    severity: 'MEDIUM',
    confidence: 0.82,
    // Must appear near a DOB / birthday / born keyword
    pattern: /\b(?:d(?:ate[\s_\-]of[\s_\-])?o(?:f[\s_\-])?b(?:irth)?|dob|born|birthday|birth[\s_\-]?date)[\s:._\-]*(\d{1,2}[\s\/\-\.]\d{1,2}[\s\/\-\.]\d{2,4}|\d{4}[\s\/\-\.]\d{1,2}[\s\/\-\.]\d{1,2})/gi,
    captureGroup: 1,
    validate: (m) => {
      // Reject dates with year outside human DOB range (1900–2020)
      const yearMatch = m.match(/\b(19\d{2}|20[01][0-9]|202[0-2])\b/);
      return yearMatch !== null;
    },
    redact: () => '[DATE OF BIRTH REDACTED]',
  },

  // ---- Indian Aadhaar Number ----------------------------------------------
  {
    id: 'INDIA_AADHAAR',
    type: 'NATIONAL_ID',
    label: 'Indian Aadhaar Number',
    category: 'identity',
    severity: 'CRITICAL',
    confidence: 0.88,
    // 12-digit number, cannot start with 0 or 1
    pattern: /\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
    validate: (m) => {
      const d = m.replace(/[\s\-]/g, '');
      return d.length === 12;
    },
    redact: (raw) => {
      const d = raw.replace(/[\s\-]/g, '');
      return 'XXXX XXXX ' + d.slice(-4);
    },
  },
];
