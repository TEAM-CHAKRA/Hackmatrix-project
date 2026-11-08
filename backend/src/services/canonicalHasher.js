import crypto from 'node:crypto';

/**
 * Canonical snapshot serializer and SHA-256 hasher (Phase 8).
 *
 * The snapshot keeps the security-relevant, stable parts of a finished report
 * and EXCLUDES (amendment 10): `demo`, `steps`, `status`, `registry`, polling
 * fields (createdAt/updatedAt/processing state), raw message text, finding
 * evidence/descriptions (they can quote the message) and the AI narrative.
 *
 * Keys are sorted recursively and arrays of objects are sorted by `id`/`key`,
 * so the same report always produces the same bytes. The exact string that was
 * hashed is stored via repository.storeCanonicalSnapshot().
 */
export const CANONICAL_VERSION = 'cyberlens-report/v1';
export const COMMUNITY_CANONICAL_VERSION = 'cyberlens-community/v1';

export function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    return Object.keys(value)
      .sort()
      .reduce((acc, k) => {
        if (value[k] !== undefined) acc[k] = sortKeys(value[k]);
        return acc;
      }, {});
  }
  return value;
}

export function canonicalize(snapshot) {
  return JSON.stringify(sortKeys(snapshot));
}

export function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

const byKey = (k) => (a, b) => String(a[k]).localeCompare(String(b[k]));
const pick = (obj, keys) => Object.fromEntries(keys.filter((k) => obj?.[k] !== undefined && obj?.[k] !== null).map((k) => [k, obj[k]]));

/** Build the canonical snapshot for a COMPLETED investigation record. */
export function buildInvestigationSnapshot(record) {
  if (!record || record.status !== 'completed') throw new Error('Only completed investigations can be snapshotted.');
  const r = { ...(record.report || {}), ...record };

  const snapshot = {
    canonicalVersion: CANONICAL_VERSION,
    id: String(r.id).toUpperCase(),
    type: r.type,
    analyzedAt: r.analyzedAt || r.completedAt,
    target: r.type === 'url' ? pick(r.target, ['display', 'host']) : { display: 'Submitted message' },
    classification: r.classification,
    confidence: r.confidence,
    heuristicScore: r.heuristicScore ?? null,
    coverage: pick(r.coverage, ['completed', 'total']),
    checks: (r.checks || []).map((c) => pick(c, ['id', 'status'])).sort(byKey('id')),
    findings: (r.findings || [])
      .map((f) => pick(f, ['id', 'title', 'severity', 'category', 'checkId', 'source']))
      .sort(byKey('id')),
  };

  if (r.type === 'url') {
    if (r.tls) snapshot.tls = { ...pick(r.tls, ['status', 'hostnameMatch', 'chainTrusted']), distrust: pick(r.tls.distrust, ['status']) };
    if (r.securityHeaders) snapshot.securityHeaders = pick(r.securityHeaders, ['status']);
    if (Array.isArray(r.redirectChain)) snapshot.redirectHops = r.redirectChain.length;
  } else if (r.type === 'message' && r.message) {
    const ind = r.message.indicators || {};
    snapshot.message = {
      tactics: (r.message.tactics || []).map((t) => pick(t, ['key', 'count'])).sort(byKey('key')),
      indicatorCounts: {
        urls: (ind.urls || []).length,
        domains: (ind.domains || []).length,
        emails: (ind.emails || []).length,
        phones: (ind.phones || []).length,
      },
    };
  }
  return snapshot;
}

/** Canonical snapshot for a VALIDATED community report. */
export function buildCommunitySnapshot(report) {
  return {
    canonicalVersion: COMMUNITY_CANONICAL_VERSION,
    id: String(report.id).toUpperCase(),
    targetType: report.targetType,
    targetDisplay: report.targetDisplay,
    category: report.category,
    description: report.description,
    submittedAt: report.submittedAt,
    status: report.status,
    validatedAt: report.validatedAt || null,
  };
}

/** → { snapshot, canonicalString, reportHash (64 lowercase hex, no 0x) } */
export function computeHash(snapshot) {
  const canonicalString = canonicalize(snapshot);
  return { snapshot, canonicalString, reportHash: sha256Hex(canonicalString) };
}
