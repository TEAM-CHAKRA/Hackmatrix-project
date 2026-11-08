import {
  CONFIRMED_MALICIOUS_CHECK_IDS,
  COMPLETED_COVERAGE_STATUSES,
} from '../config/constants.js';

/**
 * Deterministic scoring weights configuration table.
 * Easy to adjust and audit centrally.
 */
export const SCORING_WEIGHTS = {
  // Base weights by severity
  severity: {
    critical: 100, // Reachable only via confirmed checks
    high: 35,
    medium: 20,
    low: 3,
    info: 0,
  },
  // Specific adjustments on top of severity
  adjustments: {
    f_tls_distrusted_ca: 45,
    f_tls_mismatch: 40,
    f_tls_weak_crypto: 35,
    f_tls_expired: 25,
    f_tls_untrusted: 35,
    f_tls_no_https: 25,
    f_tls_valid: 0,
    f_domain_homoglyph: 45,
    f_domain_new: 20,
    typosquat: 45,
    brandInSubdomain: 45,
    headerMissing: 3,
    cookieInsecure: 3,
  },
  caps: {
    headersTotal: 10,
    maxScore: 100,
  },
};

/**
 * Determine the individual weight of a finding.
 * 
 * @param {object} finding
 * @returns {number}
 */
export function getFindingWeight(finding) {
  if (!finding) return 0;

  // Specific adjustments by finding ID
  if (finding.id === 'f_tls_distrusted_ca') return SCORING_WEIGHTS.adjustments.f_tls_distrusted_ca;
  if (finding.id === 'f_tls_mismatch') return SCORING_WEIGHTS.adjustments.f_tls_mismatch;
  if (finding.id === 'f_tls_weak_crypto') return SCORING_WEIGHTS.adjustments.f_tls_weak_crypto;
  if (finding.id === 'f_tls_expired') return SCORING_WEIGHTS.adjustments.f_tls_expired;
  if (finding.id === 'f_tls_untrusted') return SCORING_WEIGHTS.adjustments.f_tls_untrusted;
  if (finding.id === 'f_tls_no_https') return SCORING_WEIGHTS.adjustments.f_tls_no_https;
  if (finding.id === 'f_tls_valid') return SCORING_WEIGHTS.adjustments.f_tls_valid;

  if (finding.id === 'f_domain_homoglyph') return SCORING_WEIGHTS.adjustments.f_domain_homoglyph;
  if (finding.id === 'f_domain_new') return SCORING_WEIGHTS.adjustments.f_domain_new;

  if (typeof finding.id === 'string') {
    if (finding.id.startsWith('f_typo_')) return SCORING_WEIGHTS.adjustments.typosquat;
    if (finding.id.startsWith('f_subdomain_')) return SCORING_WEIGHTS.adjustments.brandInSubdomain;
    if (finding.id.startsWith('f_header_')) return SCORING_WEIGHTS.adjustments.headerMissing;
    if (finding.id.startsWith('f_cookie_insecure_')) return SCORING_WEIGHTS.adjustments.cookieInsecure;
  }

  if (finding.checkId === 'headers' && (finding.severity === 'low' || finding.severity === 'medium')) {
    return SCORING_WEIGHTS.adjustments.headerMissing;
  }

  // Fallback to base severity weight
  return SCORING_WEIGHTS.severity[finding.severity] ?? 0;
}

/**
 * Calculate deterministic heuristic risk score (0–100).
 * 
 * Rules:
 * - Score = sum of finding weights, capped at 100.
 * - Only findings from checks that completed count.
 * - Missing security headers contribute 3 each, capped at 10 in total.
 * - Same input always yields the same score.
 * 
 * @param {object} params
 * @param {Array<object>} [params.findings=[]]
 * @param {Array<{ id: string, status: string }>} [params.checks=[]]
 * @returns {{ score: number, breakdown: Array<object> }}
 */
export function calculateScore({ findings = [], checks = [] } = {}) {
  const completedCheckIds = checks.length > 0
    ? new Set(
        checks
          .filter((c) => COMPLETED_COVERAGE_STATUSES.includes(c.status))
          .map((c) => c.id)
      )
    : null;

  let headersPoints = 0;
  let otherPoints = 0;
  const breakdown = [];

  for (const f of findings) {
    if (!f) continue;

    // Findings from checks that did not complete do not count
    if (completedCheckIds && f.checkId && !completedCheckIds.has(f.checkId)) {
      continue;
    }

    const weight = getFindingWeight(f);
    if (weight === 0) continue;

    const isHeader = f.checkId === 'headers' || (typeof f.id === 'string' && f.id.startsWith('f_header_'));
    if (isHeader) {
      headersPoints += weight;
    } else {
      otherPoints += weight;
    }

    breakdown.push({
      id: f.id,
      title: f.title,
      severity: f.severity,
      weight,
    });
  }

  const cappedHeaderPoints = Math.min(SCORING_WEIGHTS.caps.headersTotal, headersPoints);
  const score = Math.min(SCORING_WEIGHTS.caps.maxScore, Math.max(0, otherPoints + cappedHeaderPoints));

  return {
    score,
    breakdown,
  };
}

/**
 * Determine investigation risk classification.
 * 
 * HARD RULE:
 * The LLM NEVER sets classification. Classification is 100% deterministic code.
 * 
 * Evaluation Order (Strict):
 * 1. confirmed_malicious: ANY check in CONFIRMED_MALICIOUS_CHECK_IDS ('gsb', 'urlhaus') has status 'match_found'.
 *    Hard Rule 2: Nothing else (TLS distrust, domain findings, community reports) can produce confirmed_malicious.
 * 2. high_risk: score >= 70.
 * 3. inconclusive: coverage.completed < total / 2 (and score < 70).
 * 4. suspicious: score 40–69.
 * 5. low_risk: score < 40 and sufficient coverage (if gsb or urlhaus was unavailable/error,
 *    cap at 'inconclusive' ONLY if coverage is also low; otherwise still low_risk, but confidence cannot be high).
 * 
 * @param {object} params
 * @param {number} params.score
 * @param {{ completed: number, total: number, missing: string[] }} params.coverage
 * @param {Array<{ id: string, status: string }>} [params.checks=[]]
 * @returns {'confirmed_malicious' | 'high_risk' | 'inconclusive' | 'suspicious' | 'low_risk'}
 */
export function calculateClassification({ score, coverage, checks = [] } = {}) {
  // Step 1: confirmed_malicious (ONLY from gsb or urlhaus returning match_found)
  const isConfirmedMalicious = checks.some(
    (c) => CONFIRMED_MALICIOUS_CHECK_IDS.includes(c.id) && c.status === 'match_found'
  );
  if (isConfirmedMalicious) {
    return 'confirmed_malicious';
  }

  // Step 2: high_risk (score >= 70)
  if (score >= 70) {
    return 'high_risk';
  }

  // Step 3: inconclusive (coverage.completed < total / 2)
  const isLowCoverage = coverage.completed < coverage.total / 2;
  if (isLowCoverage) {
    return 'inconclusive';
  }

  // Step 4: suspicious (score 40–69)
  if (score >= 40 && score <= 69) {
    return 'suspicious';
  }

  // Step 5: low_risk (score < 40 and coverage.completed >= total / 2)
  return 'low_risk';
}

/**
 * Calculate confidence level.
 * 
 * HARD RULE:
 * The LLM NEVER sets confidence.
 * 
 * Confidence Rules:
 * - 'high': coverage.completed === total AND no threat intelligence check missing or unavailable AND no contradicting evidence.
 * - 'medium': coverage.completed >= total / 2 (including cases where gsb or urlhaus was missing/unavailable).
 * - 'low': coverage.completed < total / 2.
 * 
 * @param {object} params
 * @param {'confirmed_malicious' | 'high_risk' | 'inconclusive' | 'suspicious' | 'low_risk'} params.classification
 * @param {{ completed: number, total: number, missing: string[] }} params.coverage
 * @param {Array<{ id: string, status: string }>} [params.checks=[]]
 * @returns {'high' | 'medium' | 'low'}
 */
export function calculateConfidence({ classification, coverage, checks = [] } = {}) {
  // When classification is confirmed_malicious (gsb or urlhaus match_found),
  // confidence must be "high" regardless of coverage, because the source is authoritative.
  if (classification === 'confirmed_malicious') {
    return 'high';
  }

  // If completed coverage is less than half the total, confidence is strictly low
  if (coverage.completed < coverage.total / 2) {
    return 'low';
  }

  // Missing or unavailable threat intelligence provider prevents high confidence
  const missingThreatIntel = checks.some(
    (c) => CONFIRMED_MALICIOUS_CHECK_IDS.includes(c.id) && !COMPLETED_COVERAGE_STATUSES.includes(c.status)
  );

  // Inconclusive classification cannot have high confidence
  if (classification === 'inconclusive' || missingThreatIntel) {
    return 'medium';
  }

  // High confidence requires full coverage and all threat intel checks active
  if (coverage.completed === coverage.total) {
    return 'high';
  }

  return 'medium';
}

