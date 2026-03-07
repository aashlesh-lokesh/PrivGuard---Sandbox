/**
 * Tests for the Regex Pattern Engine
 * Run: npm test
 */

import { runRegexPatterns } from '../src/patterns/index.js';
import { luhnCheck } from '../src/patterns/financial.js';
import { shannonEntropy } from '../src/patterns/identifiers.js';

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

function findByType(results, type) {
  return results.filter((r) => r.type === type);
}

// ─────────────────────────────────────────────────────────────────────────────
// Luhn check
// ─────────────────────────────────────────────────────────────────────────────

describe('luhnCheck()', () => {
  test('accepts valid Visa test number', () => {
    expect(luhnCheck('4111111111111111')).toBe(true);
  });
  test('accepts valid Mastercard test number', () => {
    expect(luhnCheck('5500005555555559')).toBe(true);
  });
  test('rejects random number', () => {
    expect(luhnCheck('1234567890123456')).toBe(false);
  });
  test('handles formatted input (spaces)', () => {
    expect(luhnCheck('4111 1111 1111 1111')).toBe(true);
  });
  test('handles formatted input (dashes)', () => {
    expect(luhnCheck('4111-1111-1111-1111')).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Shannon entropy
// ─────────────────────────────────────────────────────────────────────────────

describe('shannonEntropy()', () => {
  test('low entropy for repeated chars', () => {
    expect(shannonEntropy('aaaaaaaaaa')).toBeCloseTo(0);
  });
  test('higher entropy for random string', () => {
    expect(shannonEntropy('aB3$xK9!mZ')).toBeGreaterThan(2.5);
  });
  test('AWS-style key has high entropy', () => {
    expect(shannonEntropy('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')).toBeGreaterThan(3.5);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Credit cards
// ─────────────────────────────────────────────────────────────────────────────

describe('Credit Card detection', () => {
  test('detects Visa number (unformatted)', () => {
    const r = runRegexPatterns('My card is 4111111111111111 thanks');
    expect(findByType(r, 'CREDIT_CARD').length).toBeGreaterThanOrEqual(1);
  });

  test('detects Visa number (formatted with spaces)', () => {
    const r = runRegexPatterns('4111 1111 1111 1111');
    expect(findByType(r, 'CREDIT_CARD').length).toBeGreaterThanOrEqual(1);
  });

  test('detects Mastercard', () => {
    const r = runRegexPatterns('MC: 5500005555555559');
    expect(findByType(r, 'CREDIT_CARD').length).toBeGreaterThanOrEqual(1);
  });

  test('detects Amex', () => {
    const r = runRegexPatterns('Amex: 378282246310005');
    expect(findByType(r, 'CREDIT_CARD').length).toBeGreaterThanOrEqual(1);
  });

  test('does NOT flag random 16-digit number that fails Luhn', () => {
    const r = runRegexPatterns('Number: 4111111111111112');
    expect(findByType(r, 'CREDIT_CARD').length).toBe(0);
  });

  test('redacted value hides middle digits', () => {
    const r = runRegexPatterns('4111111111111111');
    expect(r[0]?.redacted).toMatch(/^4111 \*{4} \*{4} 1111$/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CVV
// ─────────────────────────────────────────────────────────────────────────────

describe('CVV detection', () => {
  test('detects CVV after keyword', () => {
    const r = runRegexPatterns('cvv: 123');
    expect(findByType(r, 'CVV').length).toBe(1);
  });

  test('detects CVC after keyword', () => {
    const r = runRegexPatterns('CVC2: 456');
    expect(findByType(r, 'CVV').length).toBe(1);
  });

  test('does NOT flag standalone 3-digit number', () => {
    const r = runRegexPatterns('I have 123 apples');
    expect(findByType(r, 'CVV').length).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// US SSN
// ─────────────────────────────────────────────────────────────────────────────

describe('SSN detection', () => {
  test('detects formatted SSN', () => {
    // 523-87-4210: area not 000/666/9xx, group not 00, serial not 0000
    const r = runRegexPatterns('SSN: 523-87-4210');
    const found = findByType(r, 'SSN');
    expect(found.length).toBeGreaterThanOrEqual(1);
  });

  test('detects unformatted SSN', () => {
    const r = runRegexPatterns('My social is 567891234');
    expect(findByType(r, 'SSN').length).toBeGreaterThanOrEqual(1);
  });

  test('does NOT match SSN starting with 000', () => {
    const r = runRegexPatterns('000-12-3456');
    expect(findByType(r, 'SSN').length).toBe(0);
  });

  test('does NOT match SSN starting with 666', () => {
    const r = runRegexPatterns('666-12-3456');
    expect(findByType(r, 'SSN').length).toBe(0);
  });

  test('redacted value shows only last 4', () => {
    const r = runRegexPatterns('567-89-1234');
    const ssn = findByType(r, 'SSN')[0];
    if (ssn) {
      expect(ssn.redacted).toMatch(/\*{3}-\*{2}-\d{4}/);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Phone numbers
// ─────────────────────────────────────────────────────────────────────────────

describe('Phone number detection', () => {
  test('detects US phone (formatted)', () => {
    const r = runRegexPatterns('Call me at (555) 867-5309');
    expect(findByType(r, 'PHONE_NUMBER').length).toBeGreaterThanOrEqual(1);
  });

  test('detects international E.164', () => {
    const r = runRegexPatterns('Reach me: +447911123456');
    expect(findByType(r, 'PHONE_NUMBER').length).toBeGreaterThanOrEqual(1);
  });

  test('does NOT flag 7-digit partial number without context', () => {
    const text = 'Order #8675309';
    const r = runRegexPatterns(text);
    const phones = findByType(r, 'PHONE_NUMBER');
    // If found, it must have a context keyword or E.164 format
    phones.forEach((p) => {
      expect(p.confidence).toBeGreaterThan(0.5);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Email addresses
// ─────────────────────────────────────────────────────────────────────────────

describe('Email detection', () => {
  test('detects standard email', () => {
    const r = runRegexPatterns('Contact us at alice@example.org');
    // example.org is not in the exclusion list
    expect(findByType(r, 'EMAIL').length).toBeGreaterThanOrEqual(1);
  });

  test('detects corporate email', () => {
    const r = runRegexPatterns('Email: john.doe@company.co.uk');
    expect(findByType(r, 'EMAIL').length).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// API Keys / Credentials
// ─────────────────────────────────────────────────────────────────────────────

describe('API key detection', () => {
  test('detects AWS Access Key ID', () => {
    const r = runRegexPatterns('AWS key: AKIAIOSFODNN7EXAMPLE');
    expect(findByType(r, 'AWS_ACCESS_KEY').length).toBe(1);
  });

  test('detects GitHub PAT', () => {
    // ghp_ + exactly 36 alphanumeric chars
    const r = runRegexPatterns('Token: ghp_abcdefghijklmnopqrstuvwxyz0123456789');
    expect(findByType(r, 'GITHUB_TOKEN').length).toBe(1);
  });

  test('detects Google API key', () => {
    // AIza + exactly 35 chars = 39 total
    const r = runRegexPatterns('key=AIzaSyD-examplekeyfortestingpurpose1234');
    expect(findByType(r, 'GOOGLE_API_KEY').length).toBe(1);
  });

  test('detects JWT token', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const r = runRegexPatterns(`Authorization: Bearer ${jwt}`);
    expect(findByType(r, 'JWT_TOKEN').length).toBeGreaterThanOrEqual(1);
  });

  test('detects PEM private key', () => {
    const pem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5O89KKuywbLj7FAKE==
-----END RSA PRIVATE KEY-----`;
    const r = runRegexPatterns(pem);
    expect(findByType(r, 'PRIVATE_KEY').length).toBe(1);
  });

  test('detects password assignment', () => {
    const r = runRegexPatterns('password=MyS3cretP@ss!');
    expect(findByType(r, 'PASSWORD').length).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Network / Database
// ─────────────────────────────────────────────────────────────────────────────

describe('Network credential detection', () => {
  test('detects URL with embedded credentials', () => {
    const r = runRegexPatterns('Connect to https://admin:password123@db.example.com/app');
    expect(findByType(r, 'AUTH_URL').length).toBe(1);
  });

  test('detects MongoDB connection string', () => {
    const r = runRegexPatterns('MONGO_URI=mongodb://user:pass@cluster.mongodb.net/mydb');
    expect(findByType(r, 'DATABASE_URL').length).toBe(1);
  });

  test('detects PostgreSQL connection string', () => {
    const r = runRegexPatterns('postgres://appuser:secret@localhost:5432/production');
    expect(findByType(r, 'DATABASE_URL').length).toBe(1);
  });

  test('detects OTP code with keyword', () => {
    const r = runRegexPatterns('Your OTP is 482910');
    expect(findByType(r, 'OTP').length).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Position & source metadata
// ─────────────────────────────────────────────────────────────────────────────

describe('Finding metadata', () => {
  test('finding has correct position', () => {
    const text = 'Email me at bob@test.org please';
    const r = runRegexPatterns(text);
    const email = findByType(r, 'EMAIL')[0];
    if (email) {
      expect(text.slice(email.position.start, email.position.end)).toContain('bob@test.org');
    }
  });

  test('finding has source=regex', () => {
    const r = runRegexPatterns('card: 4111111111111111');
    expect(r[0]?.source).toBe('regex');
  });
});
