/**
 * Identifier & Credentials Pattern Definitions
 * Detects: API Keys, Cloud Credentials, Tokens, Private Keys, Passwords
 */

// ---------------------------------------------------------------------------
// Shannon entropy – detects high-entropy strings (likely secrets)
// ---------------------------------------------------------------------------
export function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / str.length;
    return sum + p * Math.log2(p);
  }, 0);
}

// Threshold: a random 32-char base64 string has entropy ≈ 5.7
const HIGH_ENTROPY_THRESHOLD = 3.5;

function isHighEntropy(str) {
  return str.length >= 20 && shannonEntropy(str) >= HIGH_ENTROPY_THRESHOLD;
}

// ---------------------------------------------------------------------------
// Redaction helpers
// ---------------------------------------------------------------------------
function redactToken(raw) {
  if (raw.length <= 8) return '[TOKEN REDACTED]';
  return raw.slice(0, 4) + '...' + raw.slice(-4);
}

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------
export const IDENTIFIER_PATTERNS = [
  // ---- AWS ----------------------------------------------------------------
  {
    id: 'AWS_ACCESS_KEY_ID',
    type: 'AWS_ACCESS_KEY',
    label: 'AWS Access Key ID',
    category: 'credentials',
    severity: 'CRITICAL',
    confidence: 0.99,
    // AWS access key IDs always start with AKIA followed by 16 uppercase alphanumeric
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    redact: redactToken,
  },
  {
    id: 'AWS_SECRET_ACCESS_KEY',
    type: 'AWS_SECRET_KEY',
    label: 'AWS Secret Access Key',
    category: 'credentials',
    severity: 'CRITICAL',
    confidence: 0.90,
    // 40-char base64 string following an aws_secret_access_key label
    pattern: /\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_secret)[\s:="']*([A-Za-z0-9\/+]{40})\b/g,
    captureGroup: 1,
    redact: redactToken,
  },

  // ---- GitHub -------------------------------------------------------------
  {
    id: 'GITHUB_PAT_CLASSIC',
    type: 'GITHUB_TOKEN',
    label: 'GitHub Personal Access Token (Classic)',
    category: 'credentials',
    severity: 'CRITICAL',
    confidence: 0.99,
    pattern: /\b(ghp_[0-9a-zA-Z]{36})\b/g,
    redact: redactToken,
  },
  {
    id: 'GITHUB_PAT_FINE_GRAINED',
    type: 'GITHUB_TOKEN',
    label: 'GitHub Fine-Grained Personal Access Token',
    category: 'credentials',
    severity: 'CRITICAL',
    confidence: 0.99,
    pattern: /\b(github_pat_[0-9a-zA-Z_]{82})\b/g,
    redact: redactToken,
  },
  {
    id: 'GITHUB_OAUTH_TOKEN',
    type: 'GITHUB_TOKEN',
    label: 'GitHub OAuth Token',
    category: 'credentials',
    severity: 'CRITICAL',
    confidence: 0.99,
    pattern: /\b(gho_[0-9a-zA-Z]{36})\b/g,
    redact: redactToken,
  },
  {
    id: 'GITHUB_ACTIONS_TOKEN',
    type: 'GITHUB_TOKEN',
    label: 'GitHub Actions Token',
    category: 'credentials',
    severity: 'CRITICAL',
    confidence: 0.99,
    pattern: /\b(ghs_[0-9a-zA-Z]{36})\b/g,
    redact: redactToken,
  },

  // ---- Google -------------------------------------------------------------
  {
    id: 'GOOGLE_API_KEY',
    type: 'GOOGLE_API_KEY',
    label: 'Google API Key',
    category: 'credentials',
    severity: 'HIGH',
    confidence: 0.99,
    pattern: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    redact: redactToken,
  },

  // ---- Stripe -------------------------------------------------------------
  {
    id: 'STRIPE_SECRET_KEY',
    type: 'STRIPE_KEY',
    label: 'Stripe Secret API Key',
    category: 'credentials',
    severity: 'CRITICAL',
    confidence: 0.99,
    pattern: /\b(sk_live_[0-9a-zA-Z]{24,34})\b/g,
    redact: redactToken,
  },
  {
    id: 'STRIPE_PUBLISHABLE_KEY',
    type: 'STRIPE_KEY',
    label: 'Stripe Publishable API Key',
    category: 'credentials',
    severity: 'MEDIUM',
    confidence: 0.99,
    pattern: /\b(pk_live_[0-9a-zA-Z]{24,34})\b/g,
    redact: redactToken,
  },
  {
    id: 'STRIPE_TEST_SECRET_KEY',
    type: 'STRIPE_KEY',
    label: 'Stripe Test Secret Key',
    category: 'credentials',
    severity: 'MEDIUM',
    confidence: 0.99,
    pattern: /\b(sk_test_[0-9a-zA-Z]{24,34})\b/g,
    redact: redactToken,
  },

  // ---- SendGrid -----------------------------------------------------------
  {
    id: 'SENDGRID_API_KEY',
    type: 'SENDGRID_KEY',
    label: 'SendGrid API Key',
    category: 'credentials',
    severity: 'HIGH',
    confidence: 0.99,
    pattern: /\b(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})\b/g,
    redact: redactToken,
  },

  // ---- Twilio -------------------------------------------------------------
  {
    id: 'TWILIO_ACCOUNT_SID',
    type: 'TWILIO_KEY',
    label: 'Twilio Account SID',
    category: 'credentials',
    severity: 'HIGH',
    confidence: 0.95,
    pattern: /\b(AC[0-9a-fA-F]{32})\b/g,
    redact: redactToken,
  },
  {
    id: 'TWILIO_AUTH_TOKEN',
    type: 'TWILIO_KEY',
    label: 'Twilio Auth Token',
    category: 'credentials',
    severity: 'CRITICAL',
    confidence: 0.85,
    // 32 hex chars following a twilio auth token label
    pattern: /\b(?:twilio[\s_-]?auth[\s_-]?token|TWILIO_AUTH_TOKEN)[\s:="']*([0-9a-fA-F]{32})\b/g,
    captureGroup: 1,
    redact: redactToken,
  },

  // ---- JWT Tokens ---------------------------------------------------------
  {
    id: 'JWT_TOKEN',
    type: 'JWT_TOKEN',
    label: 'JSON Web Token (JWT)',
    category: 'credentials',
    severity: 'HIGH',
    confidence: 0.97,
    // JWT format: base64url.base64url.base64url (header starts with eyJ)
    pattern: /\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-+/=]*)\b/g,
    redact: (raw) => {
      const parts = raw.split('.');
      return `${parts[0]}.[payload redacted].${parts[2].slice(0, 4)}...`;
    },
  },

  // ---- Private Keys (PEM) ------------------------------------------------
  {
    id: 'PEM_PRIVATE_KEY',
    type: 'PRIVATE_KEY',
    label: 'PEM Private Key',
    category: 'credentials',
    severity: 'CRITICAL',
    confidence: 0.99,
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    redact: () => '[PRIVATE KEY REDACTED]',
  },

  // ---- Password in plaintext ---------------------------------------------
  {
    id: 'PASSWORD_IN_TEXT',
    type: 'PASSWORD',
    label: 'Password in Plaintext',
    category: 'credentials',
    severity: 'HIGH',
    confidence: 0.80,
    // password=value, password: value, "password": "value"
    pattern: /\b(?:password|passwd|pwd|pass|secret|credentials?)[\s]*[=:]["']?\s*([^\s"'}{,;]{6,})/gi,
    captureGroup: 1,
    redact: () => '[PASSWORD REDACTED]',
  },

  // ---- Generic High-Entropy API Keys -------------------------------------
  {
    id: 'GENERIC_API_KEY',
    type: 'GENERIC_API_KEY',
    label: 'Generic API Key / Secret',
    category: 'credentials',
    severity: 'MEDIUM',
    confidence: 0.60,
    // Must follow a key/token/secret label and be high-entropy
    pattern: /\b(?:api[_\-\s]?(?:key|secret|token)|auth[_\-\s]?(?:key|token)|access[_\-\s]?(?:key|token))[\s:="']+([A-Za-z0-9_\-+/]{20,64})\b/gi,
    captureGroup: 1,
    validate: (m) => isHighEntropy(m),
    redact: redactToken,
  },

  // ---- NPM Auth Token ---------------------------------------------------
  {
    id: 'NPM_AUTH_TOKEN',
    type: 'GENERIC_API_KEY',
    label: 'NPM Auth Token',
    category: 'credentials',
    severity: 'HIGH',
    confidence: 0.99,
    pattern: /\b(npm_[a-zA-Z0-9]{36})\b/g,
    redact: redactToken,
  },
];
