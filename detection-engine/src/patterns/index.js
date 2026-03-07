/**
 * Pattern Registry & Regex Runner
 * Aggregates all pattern modules and runs them against input text.
 */

import { FINANCIAL_PATTERNS } from './financial.js';
import { IDENTIFIER_PATTERNS } from './identifiers.js';
import { PERSONAL_PATTERNS } from './personal.js';
import { CONTACT_PATTERNS } from './contact.js';
import { NETWORK_PATTERNS } from './network.js';

// All patterns in priority order (highest-severity first to short-circuit)
export const ALL_PATTERNS = [
  ...IDENTIFIER_PATTERNS,  // credentials are highest risk
  ...FINANCIAL_PATTERNS,
  ...PERSONAL_PATTERNS,
  ...NETWORK_PATTERNS,
  ...CONTACT_PATTERNS,
];

/**
 * Runs all regex patterns against the supplied text.
 *
 * @param {string} text - The input string to scan.
 * @returns {import('../DetectionEngine.js').Finding[]} An array of Finding objects.
 */
export function runRegexPatterns(text) {
  if (!text || typeof text !== 'string') return [];

  const findings = [];

  for (const patternDef of ALL_PATTERNS) {
    // Clone the RegExp to reset lastIndex for each call (patterns have /g flag)
    const re = new RegExp(patternDef.pattern.source, patternDef.pattern.flags);
    let match;

    while ((match = re.exec(text)) !== null) {
      // Extract the relevant value: either a capture group or the full match
      const fullMatch = match[0];
      const capturedValue = patternDef.captureGroup != null
        ? match[patternDef.captureGroup]
        : fullMatch;

      if (!capturedValue) continue;

      // Run optional validator to reduce false positives
      if (patternDef.validate && !patternDef.validate(capturedValue)) continue;

      const start = match.index;
      const end = match.index + fullMatch.length;

      // Avoid emitting a finding that is fully contained inside an already-found
      // finding of the same or higher confidence (prevents duplicate sub-matches)
      const isDuplicate = findings.some(
        (f) => f.source === 'regex' && f.position.start <= start && f.position.end >= end,
      );
      if (isDuplicate) continue;

      findings.push({
        id: `${patternDef.id}_${start}`,
        type: patternDef.type,
        patternId: patternDef.id,
        label: patternDef.label,
        category: patternDef.category,
        severity: patternDef.severity,
        confidence: patternDef.confidence,
        value: capturedValue,
        rawMatch: fullMatch,
        redacted: patternDef.redact ? patternDef.redact(capturedValue) : '[REDACTED]',
        position: { start, end },
        source: 'regex',
      });

      // Avoid infinite loop on zero-width matches
      if (fullMatch.length === 0) re.lastIndex++;
    }
  }

  return findings;
}
