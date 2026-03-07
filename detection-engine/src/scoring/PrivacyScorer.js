/**
 * Privacy Risk Scorer
 *
 * Calculates a normalised 0-100 Privacy Risk Score from a set of findings.
 *
 * Algorithm overview:
 *  1. Look up the base sensitivity weight for each finding type.
 *  2. Apply diminishing returns for duplicate types (each extra hit adds 50% of base).
 *  3. Apply category-level combination multipliers (e.g. card+CVV = 1.8×).
 *  4. Apply finding-level combination multipliers (e.g. SSN + DOB = 1.4×).
 *  5. Normalise the raw score to 0-100 and assign a risk level label.
 */

// ---------------------------------------------------------------------------
// Sensitivity weight table  (max single-item score that contributes)
// Each value represents the maximum point contribution from one instance.
// ---------------------------------------------------------------------------
export const SENSITIVITY_WEIGHTS = {
  // Credentials (most dangerous)
  AWS_ACCESS_KEY:    55,
  AWS_SECRET_KEY:    65,
  GITHUB_TOKEN:      55,
  GOOGLE_API_KEY:    45,
  STRIPE_KEY:        50,
  SENDGRID_KEY:      45,
  TWILIO_KEY:        45,
  JWT_TOKEN:         30,
  PRIVATE_KEY:       70,
  PASSWORD:          45,
  GENERIC_API_KEY:   35,
  BEARER_TOKEN:      30,
  DATABASE_URL:      55,

  // Financial
  CREDIT_CARD:       40,
  CVV:               30,
  CARD_EXPIRY:       10,
  BANK_ACCOUNT:      35,
  ROUTING_NUMBER:    20,
  IBAN:              35,

  // Identity
  SSN:               55,
  NATIONAL_ID:       45,
  PASSPORT:          45,
  DRIVERS_LICENSE:   35,
  DATE_OF_BIRTH:     15,

  // Network / Infrastructure
  AUTH_URL:          30,
  IP_WITH_AUTH:      20,
  OTP:               35,

  // Contact
  PHONE_NUMBER:      15,
  EMAIL:              8,

  // NLP-detected
  ADDRESS:           20,
  PERSON_NAME:       10,
  ORGANIZATION:       5,
  SENSITIVE_PHRASE:  15,
  SENSITIVE_CONTEXT: 12,
};

// ---------------------------------------------------------------------------
// Combination multiplier rules
// Applied when ALL listed types are present in the findings.
// Multipliers stack multiplicatively if multiple rules match.
// ---------------------------------------------------------------------------
const COMBINATION_RULES = [
  {
    name: 'Full Payment Card Profile',
    requires: ['CREDIT_CARD', 'CVV', 'CARD_EXPIRY'],
    multiplier: 1.8,
  },
  {
    name: 'Partial Payment Card Data',
    requires: ['CREDIT_CARD', 'CVV'],
    multiplier: 1.5,
  },
  {
    name: 'Identity Core',
    requires: ['SSN', 'DATE_OF_BIRTH'],
    multiplier: 1.4,
  },
  {
    name: 'Identity Profile',
    requires: ['SSN', 'DATE_OF_BIRTH', 'ADDRESS'],
    multiplier: 1.6,
  },
  {
    name: 'Personal Profile (Name + Address + DOB)',
    requires: ['PERSON_NAME', 'ADDRESS', 'DATE_OF_BIRTH'],
    multiplier: 1.35,
  },
  {
    name: 'AWS Full Credential Pair',
    requires: ['AWS_ACCESS_KEY', 'AWS_SECRET_KEY'],
    multiplier: 2.0,
  },
  {
    name: 'Credential + DB Access',
    requires: ['PASSWORD', 'DATABASE_URL'],
    multiplier: 1.5,
  },
  {
    name: 'Token + Identity',
    requires: ['JWT_TOKEN', 'PERSON_NAME'],
    multiplier: 1.25,
  },
  {
    name: 'Banking Profile',
    requires: ['BANK_ACCOUNT', 'ROUTING_NUMBER'],
    multiplier: 1.45,
  },
];

// ---------------------------------------------------------------------------
// Risk level thresholds
// ---------------------------------------------------------------------------
const RISK_LEVELS = [
  { level: 'CRITICAL', minScore: 80, color: '#D32F2F', emoji: '🔴' },
  { level: 'HIGH',     minScore: 55, color: '#F57C00', emoji: '🟠' },
  { level: 'MEDIUM',   minScore: 30, color: '#FBC02D', emoji: '🟡' },
  { level: 'LOW',      minScore:  1, color: '#388E3C', emoji: '🟢' },
  { level: 'NONE',     minScore:  0, color: '#757575', emoji: '⚪' },
];

// Normalisation cap: the highest base weight (PRIVATE_KEY = 70) maps to 100.
// Combinations/multipliers push the raw score above this cap and are safely
// clamped by Math.min(100, ...) in the final step.
const NORMALISATION_CAP = 70;

// ---------------------------------------------------------------------------
// PrivacyScorer class
// ---------------------------------------------------------------------------
export class PrivacyScorer {
  /**
   * Compute the Privacy Risk Score from an array of findings.
   *
   * @param {import('../DetectionEngine.js').Finding[]} findings
   * @returns {ScoreResult}
   */
  score(findings) {
    if (!findings || findings.length === 0) {
      return this._buildResult(0, [], findings || []);
    }

    // ------------------------------------------------------------------
    // Step 1: Deduplicate by type and calculate base contribution
    // ------------------------------------------------------------------
    const byType = this._groupByType(findings);
    let rawScore = 0;

    for (const [type, instances] of Object.entries(byType)) {
      const baseWeight = SENSITIVITY_WEIGHTS[type] ?? 5;

      // First instance contributes full weight
      rawScore += baseWeight;

      // Each additional instance of the same type adds 40% (diminishing returns)
      if (instances.length > 1) {
        rawScore += (instances.length - 1) * baseWeight * 0.40;
      }
    }

    // ------------------------------------------------------------------
    // Step 2: Identify which combination rules match
    // ------------------------------------------------------------------
    const presentTypes = new Set(Object.keys(byType));
    const matchedRules = COMBINATION_RULES.filter((rule) =>
      rule.requires.every((t) => presentTypes.has(t)),
    );

    // ------------------------------------------------------------------
    // Step 3: Apply combination multipliers (multiplicative stacking)
    // ------------------------------------------------------------------
    let multiplier = 1.0;
    for (const rule of matchedRules) {
      multiplier *= rule.multiplier;
    }
    rawScore *= multiplier;

    // ------------------------------------------------------------------
    // Step 4: Normalise to 0-100
    // ------------------------------------------------------------------
    const normalised = Math.min(100, Math.round((rawScore / NORMALISATION_CAP) * 100));

    return this._buildResult(normalised, matchedRules, findings);
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /** Group findings by their type field */
  _groupByType(findings) {
    return findings.reduce((acc, f) => {
      (acc[f.type] = acc[f.type] || []).push(f);
      return acc;
    }, {});
  }

  /** Determine risk level from normalised score */
  _riskLevel(score) {
    return RISK_LEVELS.find((r) => score >= r.minScore) ?? RISK_LEVELS.at(-1);
  }

  /** Summarise findings by category */
  _categorySummary(findings) {
    const counts = {};
    for (const f of findings) {
      counts[f.category] = (counts[f.category] || 0) + 1;
    }
    return counts;
  }

  /** Build the final structured result */
  _buildResult(score, matchedRules, findings) {
    const risk = this._riskLevel(score);
    const byType = this._groupByType(findings);

    // Highest-weight finding type present
    const highestRisk = Object.keys(byType).sort(
      (a, b) => (SENSITIVITY_WEIGHTS[b] ?? 0) - (SENSITIVITY_WEIGHTS[a] ?? 0),
    )[0] ?? null;

    return {
      score,
      riskLevel: risk.level,
      riskColor: risk.color,
      riskEmoji: risk.emoji,
      summary: {
        totalFindings: findings.length,
        uniqueTypes: Object.keys(byType).length,
        byCategory: this._categorySummary(findings),
        highestRiskType: highestRisk,
        appliedMultipliers: matchedRules.map((r) => ({
          name: r.name,
          multiplier: r.multiplier,
        })),
      },
    };
  }
}

/**
 * @typedef {object} ScoreResult
 * @property {number}  score           - Normalised score 0-100
 * @property {string}  riskLevel       - 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
 * @property {string}  riskColor       - Hex colour for UI
 * @property {string}  riskEmoji       - Emoji indicator for UI
 * @property {object}  summary
 * @property {number}  summary.totalFindings
 * @property {number}  summary.uniqueTypes
 * @property {object}  summary.byCategory
 * @property {string|null} summary.highestRiskType
 * @property {Array<{name:string,multiplier:number}>} summary.appliedMultipliers
 */

export default PrivacyScorer;
