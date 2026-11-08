// CYBERLENS Shared Enums and Constants
// Strictly aligned with docs/api-contract.md and frontend/src/utils/constants.js

export const ERROR_CODES = {
  VALIDATION_ERROR: 'VALIDATION_ERROR', // 400
  SSRF_BLOCKED: 'SSRF_BLOCKED',         // 400
  NOT_AUTHENTICATED: 'NOT_AUTHENTICATED', // 401 (not signed in / session expired)
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS', // 401 (generic login failure)
  FORBIDDEN: 'FORBIDDEN',               // 403 (signed in, wrong role)
  CSRF_INVALID: 'CSRF_INVALID',         // 403
  NOT_FOUND: 'NOT_FOUND',               // 404
  CONFLICT: 'CONFLICT',                 // 409 (state does not allow the action)
  EMAIL_TAKEN: 'EMAIL_TAKEN',           // 409
  PAYLOAD_TOO_LARGE: 'PAYLOAD_TOO_LARGE', // 413
  RATE_LIMITED: 'RATE_LIMITED',         // 429
  PROVIDER_ERROR: 'PROVIDER_ERROR',     // 502
  CHAIN_UNAVAILABLE: 'CHAIN_UNAVAILABLE',// 503
  NOT_READY: 'NOT_READY',               // 503
  INTERNAL: 'INTERNAL',                 // 500
  SERVER_STARTING: 'SERVER_STARTING',   // 503 (still connecting to the database after a restart)
};

export const USER_ROLES = ['user', 'admin'];

export const CLASSIFICATIONS = [
  'low_risk',
  'suspicious',
  'high_risk',
  'confirmed_malicious',
  'inconclusive',
];

export const CONFIDENCE_LEVELS = ['low', 'medium', 'high'];

export const CHECK_STATUSES = [
  'completed',
  'no_match',
  'match_found',
  'unavailable',
  'error',
  'not_checked',
];

// Coverage rule: only these statuses count toward completed coverage
export const COMPLETED_COVERAGE_STATUSES = ['completed', 'no_match', 'match_found'];

export const STEP_STATUSES = ['pending', 'running', 'completed', 'failed', 'skipped'];

export const FINDING_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export const FINDING_CATEGORIES = ['confirmed', 'heuristic', 'weakness', 'informational'];

export const REPORT_STATUSES = ['processing', 'completed', 'failed'];

export const REGISTRY_STATUSES = ['not_registered', 'pending', 'registered', 'failed'];

export const TLS_STATUSES = [
  'valid',
  'expired',
  'hostname_mismatch',
  'untrusted_chain',
  'incomplete',
  'unavailable',
  'no_https',
  'weak_crypto',
];

export const TLS_DISTRUST_STATUSES = ['no_match', 'match_found', 'not_checked'];

export const COMMUNITY_REPORT_STATUSES = [
  'pending_review',
  'under_review',
  'validated',
  'disputed',
  'rejected',
];

export const MESSAGE_TACTIC_KEYS = [
  'urgency',
  'threat',
  'impersonation',
  'fake_reward',
  'account_suspension',
  'otp_request',
  'password_request',
  'payment_request',
  'suspicious_link',
  'social_engineering',
];

export const THREAT_CATEGORIES = [
  'phishing',
  'scam',
  'malware',
  'impersonation',
  'fake_shop',
  'investment_fraud',
  'other',
];

// Fixed check IDs for URL investigations (Total: 6)
export const URL_CHECK_IDS = ['gsb', 'urlhaus', 'domain', 'tls', 'ct', 'headers'];

/**
 * Classifier rule: confirmed_malicious comes ONLY from a "match_found" on the checks with ids gsb or urlhaus.
 * Distrusted CAs, heuristic findings, or other check failures do not produce confirmed_malicious.
 */
// 'threat_intel' is the MESSAGE-flow check that wraps the same two providers
// (GSB + URLhaus lookups of links extracted from the message). Its status is
// match_found ONLY when one of those providers matched (Phase 4).
export const CONFIRMED_MALICIOUS_CHECK_IDS = ['gsb', 'urlhaus', 'threat_intel'];

// Fixed check IDs for Message investigations (Total: 4)
export const MESSAGE_CHECK_IDS = ['indicators', 'tactics', 'threat_intel', 'links'];

export const DEFAULT_STEPS = {
  url: [
    { key: 'submission', label: 'Submission received', status: 'completed' },
    { key: 'investigation', label: 'URL investigation', status: 'pending' },
    { key: 'threat_intel', label: 'Threat intelligence analysis', status: 'pending' },
    { key: 'tls_security', label: 'TLS and security assessment', status: 'pending' },
    { key: 'risk_report', label: 'Risk assessment and report', status: 'pending' },
  ],
  message: [
    { key: 'submission', label: 'Submission received', status: 'completed' },
    { key: 'investigation', label: 'Message investigation', status: 'pending' },
    { key: 'threat_intel', label: 'Threat intelligence analysis', status: 'pending' },
    { key: 'tls_security', label: 'Indicator verification', status: 'pending' },
    { key: 'risk_report', label: 'Risk assessment and report', status: 'pending' },
  ],
};

