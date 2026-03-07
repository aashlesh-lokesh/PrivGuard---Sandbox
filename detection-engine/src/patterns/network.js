/**
 * Network & Infrastructure Pattern Definitions
 * Detects: URLs with Credentials, Database Connection Strings, IP-based Auth, OTPs
 */

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------
export const NETWORK_PATTERNS = [
  // ---- URLs with Embedded Credentials ------------------------------------
  {
    id: 'URL_WITH_CREDENTIALS',
    type: 'AUTH_URL',
    label: 'URL with Embedded Credentials',
    category: 'network',
    severity: 'CRITICAL',
    confidence: 0.97,
    // https://user:password@host
    pattern: /https?:\/\/[^:\s@/]+:[^@\s@/]+@[^\s"'<>){\]]+/gi,
    redact: (raw) => raw.replace(/(https?:\/\/)[^:\s@/]+:[^@\s@/]+@/, '$1[CREDENTIALS REDACTED]@'),
  },

  // ---- Database Connection Strings ----------------------------------------
  {
    id: 'DB_CONNECTION_MONGODB',
    type: 'DATABASE_URL',
    label: 'MongoDB Connection String',
    category: 'network',
    severity: 'CRITICAL',
    confidence: 0.98,
    pattern: /mongodb(?:\+srv)?:\/\/[^\s"'<>){\]]+/gi,
    redact: (raw) => raw.replace(/:\/\/([^:\s@/]+):([^@\s@/]+)@/, '://[USER REDACTED]:[PASS REDACTED]@'),
  },
  {
    id: 'DB_CONNECTION_MYSQL',
    type: 'DATABASE_URL',
    label: 'MySQL/MariaDB Connection String',
    category: 'network',
    severity: 'CRITICAL',
    confidence: 0.98,
    pattern: /mysql(?:2)?:\/\/[^\s"'<>){\]]+/gi,
    redact: (raw) => raw.replace(/:\/\/([^:\s@/]+):([^@\s@/]+)@/, '://[USER REDACTED]:[PASS REDACTED]@'),
  },
  {
    id: 'DB_CONNECTION_POSTGRES',
    type: 'DATABASE_URL',
    label: 'PostgreSQL Connection String',
    category: 'network',
    severity: 'CRITICAL',
    confidence: 0.98,
    pattern: /postgre(?:s|sql):\/\/[^\s"'<>){\]]+/gi,
    redact: (raw) => raw.replace(/:\/\/([^:\s@/]+):([^@\s@/]+)@/, '://[USER REDACTED]:[PASS REDACTED]@'),
  },
  {
    id: 'DB_CONNECTION_REDIS',
    type: 'DATABASE_URL',
    label: 'Redis Connection String',
    category: 'network',
    severity: 'HIGH',
    confidence: 0.97,
    pattern: /rediss?:\/\/[^\s"'<>){\]]+/gi,
    redact: (raw) => raw.replace(/:\/\/([^:\s@/]+):([^@\s@/]+)@/, '://[USER REDACTED]:[PASS REDACTED]@'),
  },
  {
    id: 'DB_CONNECTION_AMQP',
    type: 'DATABASE_URL',
    label: 'AMQP (RabbitMQ) Connection String',
    category: 'network',
    severity: 'HIGH',
    confidence: 0.97,
    pattern: /amqps?:\/\/[^\s"'<>){\]]+/gi,
    redact: (raw) => raw.replace(/:\/\/([^:\s@/]+):([^@\s@/]+)@/, '://[USER REDACTED]:[PASS REDACTED]@'),
  },

  // ---- Authorization Bearer Token in HTTP headers -----------------------
  {
    id: 'BEARER_TOKEN_HEADER',
    type: 'BEARER_TOKEN',
    label: 'HTTP Authorization Bearer Token',
    category: 'network',
    severity: 'HIGH',
    confidence: 0.90,
    pattern: /Authorization[\s]*:[\s]*Bearer[\s]+([A-Za-z0-9._\-+/=]{16,512})/gi,
    captureGroup: 1,
    redact: (raw) => {
      if (raw.length <= 8) return '[TOKEN REDACTED]';
      return raw.slice(0, 6) + '...[REDACTED]...' + raw.slice(-4);
    },
  },

  // ---- OTP / Verification Codes ------------------------------------------
  {
    id: 'OTP_CODE',
    type: 'OTP',
    label: 'One-Time Password / Verification Code',
    category: 'credentials',
    severity: 'HIGH',
    confidence: 0.88,
    // Must appear near OTP/verification/code keywords; allows "Your OTP is 123456"
    pattern: /\b(?:otp|one[\s\-]?time[\s\-]?(?:password|passcode|pin|code)|verification[\s\-]?code|auth(?:entication)?[\s\-]?code|2fa[\s\-]?code|security[\s\-]?code|confirm(?:ation)?[\s\-]?code)[\s:._\-]*(?:is\s+)?([0-9]{4,8})\b/gi,
    captureGroup: 1,
    redact: () => '[OTP REDACTED]',
  },

  // ---- Private IP Address in Auth Context --------------------------------
  {
    id: 'IP_IN_CREDENTIALS',
    type: 'IP_WITH_AUTH',
    label: 'IP Address in Authentication Context',
    category: 'network',
    severity: 'MEDIUM',
    confidence: 0.70,
    // IP followed by port and preceded/followed by credential keywords
    pattern: /\b(?:server|host|endpoint|ip)[\s:._\-=]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{2,5}))?\b/gi,
    captureGroup: 1,
    validate: (m) => {
      const parts = m.split('.').map(Number);
      return parts.every(p => p >= 0 && p <= 255) &&
             !['255.255.255.255', '0.0.0.0', '127.0.0.1'].includes(m);
    },
    redact: (raw) => {
      const parts = raw.split('.');
      return `${parts[0]}.${parts[1]}.*.*`;
    },
  },

  // ---- Slack Webhook URL -------------------------------------------------
  {
    id: 'SLACK_WEBHOOK',
    type: 'GENERIC_API_KEY',
    label: 'Slack Webhook URL',
    category: 'credentials',
    severity: 'HIGH',
    confidence: 0.99,
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    redact: (raw) => raw.replace(/\/[A-Za-z0-9]{20,}$/, '/[TOKEN REDACTED]'),
  },

  // ---- Discord Webhook ---------------------------------------------------
  {
    id: 'DISCORD_WEBHOOK',
    type: 'GENERIC_API_KEY',
    label: 'Discord Webhook URL',
    category: 'credentials',
    severity: 'HIGH',
    confidence: 0.99,
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+/g,
    redact: (raw) => raw.replace(/\/[A-Za-z0-9_\-]{50,}$/, '/[TOKEN REDACTED]'),
  },
];
