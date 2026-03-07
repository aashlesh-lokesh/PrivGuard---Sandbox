/**
 * Tests for the Privacy Risk Scorer
 */

import { PrivacyScorer, SENSITIVITY_WEIGHTS } from '../src/scoring/PrivacyScorer.js';

const scorer = new PrivacyScorer();

// Convenience: create a minimal finding stub
function makeFinding(type, category = 'financial', count = 1) {
  return Array.from({ length: count }, (_, i) => ({
    id: `${type}_${i}`,
    type,
    label: type,
    category,
    severity: 'HIGH',
    confidence: 0.95,
    value: 'TEST',
    redacted: '[REDACTED]',
    position: { start: i * 10, end: i * 10 + 8 },
    source: 'regex',
  }));
}

// ─────────────────────────────────────────────────────────────────────────────

describe('PrivacyScorer – empty / no findings', () => {
  test('returns score=0 for empty array', () => {
    expect(scorer.score([]).score).toBe(0);
  });
  test('risk level is NONE for empty findings', () => {
    expect(scorer.score([]).riskLevel).toBe('NONE');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('PrivacyScorer – single findings', () => {
  test('email only → LOW risk', () => {
    const result = scorer.score(makeFinding('EMAIL', 'contact'));
    expect(result.riskLevel).toMatch(/LOW|NONE/);
    expect(result.score).toBeGreaterThan(0);
    expect(result.score).toBeLessThan(30);
  });

  test('SSN → at least HIGH risk', () => {
    const result = scorer.score(makeFinding('SSN', 'identity'));
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });

  test('private key → CRITICAL risk', () => {
    const result = scorer.score(makeFinding('PRIVATE_KEY', 'credentials'));
    expect(result.riskLevel).toBe('CRITICAL');
  });

  test('credit card alone → HIGH risk', () => {
    const result = scorer.score(makeFinding('CREDIT_CARD', 'financial'));
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('PrivacyScorer – combination multipliers', () => {
  test('CREDIT_CARD + CVV score higher than each alone', () => {
    const cardOnly = scorer.score(makeFinding('CREDIT_CARD', 'financial')).score;
    const cvvOnly  = scorer.score(makeFinding('CVV', 'financial')).score;
    const combined = scorer.score([
      ...makeFinding('CREDIT_CARD', 'financial'),
      ...makeFinding('CVV', 'financial'),
    ]).score;
    expect(combined).toBeGreaterThan(Math.max(cardOnly, cvvOnly));
  });

  test('Full payment profile (CARD + CVV + EXPIRY) triggers multiplier name', () => {
    const result = scorer.score([
      ...makeFinding('CREDIT_CARD', 'financial'),
      ...makeFinding('CVV', 'financial'),
      ...makeFinding('CARD_EXPIRY', 'financial'),
    ]);
    const names = result.summary.appliedMultipliers.map((m) => m.name);
    expect(names).toContain('Full Payment Card Profile');
  });

  test('AWS key pair triggers 2x multiplier', () => {
    const accessOnly = scorer.score(makeFinding('AWS_ACCESS_KEY', 'credentials')).score;
    const pairResult = scorer.score([
      ...makeFinding('AWS_ACCESS_KEY', 'credentials'),
      ...makeFinding('AWS_SECRET_KEY', 'credentials'),
    ]);
    expect(pairResult.score).toBeGreaterThan(accessOnly);
    const multiplierNames = pairResult.summary.appliedMultipliers.map((m) => m.name);
    expect(multiplierNames).toContain('AWS Full Credential Pair');
  });

  test('SSN + DOB triggers Identity Core multiplier', () => {
    const result = scorer.score([
      ...makeFinding('SSN', 'identity'),
      ...makeFinding('DATE_OF_BIRTH', 'identity'),
    ]);
    const names = result.summary.appliedMultipliers.map((m) => m.name);
    expect(names).toContain('Identity Core');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('PrivacyScorer – diminishing returns', () => {
  test('two emails score more than one but not double', () => {
    const one = scorer.score(makeFinding('EMAIL', 'contact', 1)).score;
    const two = scorer.score(makeFinding('EMAIL', 'contact', 2)).score;
    expect(two).toBeGreaterThan(one);
    expect(two).toBeLessThan(one * 2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('PrivacyScorer – score ceiling', () => {
  test('score never exceeds 100', () => {
    // Pile up every critical finding type
    const findings = [
      ...makeFinding('PRIVATE_KEY', 'credentials'),
      ...makeFinding('AWS_ACCESS_KEY', 'credentials'),
      ...makeFinding('AWS_SECRET_KEY', 'credentials'),
      ...makeFinding('CREDIT_CARD', 'financial'),
      ...makeFinding('CVV', 'financial'),
      ...makeFinding('CARD_EXPIRY', 'financial'),
      ...makeFinding('SSN', 'identity'),
      ...makeFinding('DATE_OF_BIRTH', 'identity'),
      ...makeFinding('ADDRESS', 'location'),
      ...makeFinding('DATABASE_URL', 'network'),
    ];
    const result = scorer.score(findings);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.riskLevel).toBe('CRITICAL');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('PrivacyScorer – summary metadata', () => {
  test('includes correct totalFindings count', () => {
    const findings = [
      ...makeFinding('EMAIL', 'contact'),
      ...makeFinding('PHONE_NUMBER', 'contact'),
      ...makeFinding('CREDIT_CARD', 'financial'),
    ];
    const result = scorer.score(findings);
    expect(result.summary.totalFindings).toBe(3);
  });

  test('byCategory groups correctly', () => {
    const findings = [
      ...makeFinding('EMAIL', 'contact'),
      ...makeFinding('PHONE_NUMBER', 'contact'),
      ...makeFinding('CREDIT_CARD', 'financial'),
    ];
    const result = scorer.score(findings);
    expect(result.summary.byCategory.contact).toBe(2);
    expect(result.summary.byCategory.financial).toBe(1);
  });

  test('highestRiskType is the most sensitive type present', () => {
    const findings = [
      ...makeFinding('EMAIL', 'contact'),
      ...makeFinding('PRIVATE_KEY', 'credentials'),
    ];
    const result = scorer.score(findings);
    expect(result.summary.highestRiskType).toBe('PRIVATE_KEY');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('PrivacyScorer – SENSITIVITY_WEIGHTS sanity', () => {
  test('AWS_SECRET_KEY weight is higher than EMAIL weight', () => {
    expect(SENSITIVITY_WEIGHTS.AWS_SECRET_KEY).toBeGreaterThan(SENSITIVITY_WEIGHTS.EMAIL);
  });
  test('PRIVATE_KEY has the highest weight', () => {
    const max = Math.max(...Object.values(SENSITIVITY_WEIGHTS));
    expect(SENSITIVITY_WEIGHTS.PRIVATE_KEY).toBe(max);
  });
});
