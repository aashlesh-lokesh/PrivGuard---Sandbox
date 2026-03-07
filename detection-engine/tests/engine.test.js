/**
 * Integration tests for DetectionEngine.analyzeText()
 * (NLP requires compromise to be installed)
 */

import DetectionEngine from '../src/DetectionEngine.js';

const engine = new DetectionEngine({ enableNLP: false }); // NLP off for unit isolation

// ─────────────────────────────────────────────────────────────────────────────

describe('DetectionEngine.analyzeText()', () => {
  test('returns no findings for clean text', async () => {
    const result = await engine.analyzeText('Hello world, the weather is nice today!');
    expect(result.findings.length).toBe(0);
    expect(result.riskLevel).toBe('NONE');
    expect(result.score).toBe(0);
  });

  test('detects credit card in mixed text', async () => {
    const result = await engine.analyzeText(
      'Hi, my Visa card is 4111111111111111 and I need help.',
    );
    const cards = result.findings.filter((f) => f.type === 'CREDIT_CARD');
    expect(cards.length).toBeGreaterThanOrEqual(1);
    expect(result.score).toBeGreaterThan(0);
  });

  test('detects multiple types and scores higher', async () => {
    const text = 'Card: 4111111111111111 CVV: 123 SSN: 567-89-1234';
    const result = await engine.analyzeText(text);
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
    expect(result.score).toBeGreaterThanOrEqual(30);
  });

  test('redactedText() removes sensitive values', async () => {
    const text = 'Email me at bob@company.io, card 4111111111111111';
    const result = await engine.analyzeText(text);
    const redacted = result.redactedText();
    expect(redacted).not.toContain('4111111111111111');
    expect(redacted).not.toContain('bob@company.io');
  });

  test('returns meta.analysedAt as ISO string', async () => {
    const result = await engine.analyzeText('test');
    expect(result.meta.analysedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  test('findings are sorted by position', async () => {
    const text = 'SSN: 123-45-6789 and Visa card 4111111111111111';
    const result = await engine.analyzeText(text);
    for (let i = 1; i < result.findings.length; i++) {
      expect(result.findings[i].position.start).toBeGreaterThanOrEqual(
        result.findings[i - 1].position.start,
      );
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('DetectionEngine – high-risk scenarios', () => {
  test('AWS credential pair → CRITICAL', async () => {
    const text = `
      AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
      aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    `;
    const result = await engine.analyzeText(text);
    expect(result.riskLevel).toBe('CRITICAL');
  });

  test('PEM private key → CRITICAL', async () => {
    const text = `
      -----BEGIN RSA PRIVATE KEY-----
      MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5O89KKuywbLj7FAKEKEY==
      -----END RSA PRIVATE KEY-----
    `;
    const result = await engine.analyzeText(text);
    expect(result.riskLevel).toBe('CRITICAL');
  });

  test('Database URL → HIGH or CRITICAL', async () => {
    const result = await engine.analyzeText(
      'DB_URL=mongodb://root:supersecret@cluster0.mongodb.net/production',
    );
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('DetectionEngine – NLP enabled', () => {
  const engineWithNlp = new DetectionEngine({ enableNLP: true });

  test('detects physical address', async () => {
    const result = await engineWithNlp.analyzeText(
      'I live at 123 Main Street, Springfield, IL 62701',
    );
    const address = result.findings.filter((f) => f.type === 'ADDRESS');
    expect(address.length).toBeGreaterThanOrEqual(1);
  });

  test('detects confidential phrase', async () => {
    const result = await engineWithNlp.analyzeText(
      'This document is strictly confidential and not for distribution.',
    );
    const phrases = result.findings.filter(
      (f) => f.type === 'SENSITIVE_PHRASE' || f.type === 'SENSITIVE_CONTEXT',
    );
    expect(phrases.length).toBeGreaterThanOrEqual(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('DetectionEngine.analyze() – empty inputs', () => {
  test('handles empty string gracefully', async () => {
    const result = await engine.analyzeText('');
    expect(result.score).toBe(0);
    expect(result.findings).toEqual([]);
  });

  test('handles undefined gracefully', async () => {
    const result = await engine.analyze({});
    expect(result.score).toBe(0);
  });
});
