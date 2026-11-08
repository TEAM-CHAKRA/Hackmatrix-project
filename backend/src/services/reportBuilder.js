import { calculateCoverage } from './coverage.js';
import {
  calculateScore,
  calculateClassification,
  calculateConfidence,
} from './heuristicEngine.js';
import { generateExplanation, extractHostname } from './aiExplainer.js';

/**
 * Build a full evaluation report combining coverage, deterministic scoring,
 * classification, confidence, and AI explanation narrative.
 * 
 * HARD RULES:
 * 1. The LLM NEVER sets classification, confidence or score.
 * 2. confirmed_malicious comes ONLY from gsb or urlhaus returning match_found.
 * 3. Unavailable/error/not_checked checks never count as completed.
 * 
 * @param {object} params
 * @param {string} [params.id] Investigation ID
 * @param {'url' | 'message'} [params.type='url']
 * @param {string|object} params.target Target URL or message text
 * @param {Array<object>} [params.checks=[]] Array of checks
 * @param {Array<object>} [params.findings=[]] Raw findings array
 * @param {object} [params.tls] TLS inspection data (URL investigations)
 * @param {object} [params.securityHeaders] HTTP security headers data
 * @param {Array<object>} [params.redirectChain] HTTP redirect chain
 * @param {object} [params.domainAnalysis] Domain analysis extras
 * @param {object} [params.message] Message investigation indicators & tactics
 * @param {Function} [params.fetchFn=globalThis.fetch] Injectable fetch for AI narrative
 * @returns {Promise<object>} Complete API contract-compliant report object
 */
export async function buildReport({
  id,
  type = 'url',
  target,
  checks = [],
  findings = [],
  tls,
  securityHeaders,
  redirectChain,
  domainAnalysis,
  message,
  fetchFn = globalThis.fetch,
} = {}) {
  // 1. Calculate check coverage
  const coverage = calculateCoverage({ type, checks });

  // 2. Collate and deduplicate findings across checks and input
  const allFindings = [...findings];
  for (const c of checks) {
    if (Array.isArray(c.findings)) {
      allFindings.push(...c.findings);
    }
  }

  const seenFindingIds = new Set();
  const dedupedFindings = [];
  for (const f of allFindings) {
    if (f && f.id && !seenFindingIds.has(f.id)) {
      seenFindingIds.add(f.id);
      dedupedFindings.push(f);
    }
  }

  // 3. Compute deterministic score (0–100)
  const { score, breakdown } = calculateScore({
    findings: dedupedFindings,
    checks,
  });

  // 4. Compute deterministic classification
  const classification = calculateClassification({
    score,
    coverage,
    checks,
  });

  // 5. Compute deterministic confidence
  const confidence = calculateConfidence({
    classification,
    coverage,
    checks,
    score,
  });

  // 6. Generate narrative explanation (Gemini API with offline template fallback)
  // Messages: never pass message text to the explainer, only a neutral label.
  const targetHost = type === 'message' ? 'submitted message' : extractHostname(target?.host || target);
  const explanationResult = await generateExplanation({
    type,
    classification,
    score,
    confidence,
    coverage,
    targetHost,
    findings: dedupedFindings,
    checks,
    fetchFn,
  });

  // 7. Assemble contract-compliant report structure
  const nowIso = new Date().toISOString();
  const processedFindings = dedupedFindings.map((f) => ({
    ...f,
    source: f.source || 'Threat Intelligence analysis',
  }));

  const report = {
    id,
    type,
    status: 'completed',
    analyzedAt: nowIso,
    classification,
    confidence,
    heuristicScore: score,
    score,
    scoreBreakdown: breakdown,
    coverage,
    findings: processedFindings,
    explanation: {
      source: explanationResult.source,
      summary: explanationResult.summary,
      keyPoints: explanationResult.keyPoints,
    },
    recommendations: explanationResult.recommendations,
    limitations: explanationResult.limitations,
    registry: { status: 'not_registered' },
  };

  if (type === 'url') {
    report.redirectChain = redirectChain || [
      { url: typeof target === 'string' ? target : target?.display || '', statusCode: 200, suspicious: false },
    ];
    report.tls = tls || { status: 'unavailable', httpsAvailable: false };
    report.securityHeaders = securityHeaders || { status: 'unavailable', headers: [], cookies: [] };
    if (domainAnalysis) {
      report.domainAnalysis = domainAnalysis;
    }
  } else if (type === 'message') {
    report.message = message || { indicators: {}, tactics: [] };
  }

  return report;
}

