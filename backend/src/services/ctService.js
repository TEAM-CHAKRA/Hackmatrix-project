import { getDomainParts } from './domainAnalyzer.js';
import { env } from '../config/env.js';

const CT_CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes
const MAX_CACHE_ENTRIES = 200;
const ctCache = new Map();

/**
 * Reset CT in-memory cache (primarily for tests)
 */
export function _resetCtCache() {
  ctCache.clear();
}

/**
 * Certificate Transparency Check via crt.sh with fallback to Cert Spotter (SSLMate).
 * 
 * Overall budget: 8 seconds (primary 5s, fallback within remaining time).
 * Successful results are cached for 15 minutes (max 200 entries). Failures are never cached.
 * 
 * @param {object} params
 * @param {string} params.hostname
 * @param {Function} [params.fetchFn] Injectable fetch for testing
 * @returns {Promise<{
 *   id: 'ct',
 *   name: 'Certificate Transparency',
 *   source: string,
 *   status: 'completed' | 'unavailable' | 'error',
 *   detail?: string,
 *   entries?: number,
 *   findings: Array<object>
 * }>}
 */
export async function checkCertificateTransparency({ hostname, fetchFn = globalThis.fetch }) {
  const cleanHost = hostname.replace(/^\[|\]$/g, '').trim();
  const { registrableDomain, isSharedHosting } = getDomainParts(cleanHost);
  const queryDomain = isSharedHosting ? cleanHost : (registrableDomain || cleanHost);

  // Check in-memory cache for successful results
  const now = Date.now();
  if (ctCache.has(queryDomain)) {
    const cached = ctCache.get(queryDomain);
    if (now < cached.expiresAt) {
      return JSON.parse(JSON.stringify(cached.result));
    }
    ctCache.delete(queryDomain);
  }

  const startTime = Date.now();
  const overallTimeoutMs = 8000;
  const primaryTimeoutMs = 5000;

  let primarySuccess = false;
  let primaryEntries = 0;
  let shouldFallback = false;

  // 1. Primary Provider: crt.sh (5s budget)
  const primaryController = new AbortController();
  const primaryTimer = setTimeout(() => primaryController.abort(), primaryTimeoutMs);

  try {
    const crtUrl = `https://crt.sh/?q=${encodeURIComponent(queryDomain)}&output=json&exclude=expired&deduplicate=Y`;
    const res = await fetchFn(crtUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'CyberLens-Scanner/1.0',
        Accept: 'application/json',
      },
      signal: primaryController.signal,
    });

    if (res.ok) {
      const data = await res.json();
      primaryEntries = Array.isArray(data) ? data.length : 0;
      primarySuccess = true;
    } else if (res.status >= 500) {
      shouldFallback = true;
    }
  } catch {
    shouldFallback = true;
  } finally {
    clearTimeout(primaryTimer);
  }

  if (primarySuccess) {
    const result = {
      id: 'ct',
      name: 'Certificate Transparency',
      source: 'crt.sh',
      status: 'completed',
      detail: `${primaryEntries} log entries recorded in public Certificate Transparency logs`,
      entries: primaryEntries,
      findings: [
        {
          id: 'f_ct_entries',
          title: 'Certificate Transparency logs verified',
          description: `Found ${primaryEntries} Certificate Transparency entries for this domain in public logs.`,
          severity: 'info',
          category: 'informational',
          source: 'crt.sh',
          checkId: 'ct',
          evidence: { 'CT entries found': String(primaryEntries) },
        },
      ],
    };

    // Cache successful result (max 200 entries, 15 min TTL)
    if (ctCache.size >= MAX_CACHE_ENTRIES) {
      ctCache.delete(ctCache.keys().next().value);
    }
    ctCache.set(queryDomain, { result, expiresAt: Date.now() + CT_CACHE_TTL_MS });

    return result;
  }

  // 2. Fallback Provider: Cert Spotter (SSLMate) within remaining time
  const elapsed = Date.now() - startTime;
  const remainingBudgetMs = overallTimeoutMs - elapsed;

  if (shouldFallback && remainingBudgetMs > 100) {
    const fallbackController = new AbortController();
    const fallbackTimer = setTimeout(() => fallbackController.abort(), remainingBudgetMs);

    try {
      const certspotterUrl = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(queryDomain)}&include_subdomains=true`;
      const headers = {
        'User-Agent': 'CyberLens-Scanner/1.0',
        Accept: 'application/json',
      };
      const apiKey = env.CERTSPOTTER_API_KEY || process.env.CERTSPOTTER_API_KEY;
      if (apiKey) {
        headers['Authorization'] = `Bearer ${apiKey}`;
      }

      const res = await fetchFn(certspotterUrl, {
        method: 'GET',
        headers,
        signal: fallbackController.signal,
      });

      if (res.ok) {
        const data = await res.json();
        const fallbackEntries = Array.isArray(data) ? data.length : 0;
        const result = {
          id: 'ct',
          name: 'Certificate Transparency',
          source: 'Cert Spotter (fallback)',
          status: 'completed',
          detail: `${fallbackEntries} log entries recorded in public Certificate Transparency logs`,
          entries: fallbackEntries,
          findings: [
            {
              id: 'f_ct_entries',
              title: 'Certificate Transparency logs verified',
              description: `Found ${fallbackEntries} Certificate Transparency entries for this domain in public logs.`,
              severity: 'info',
              category: 'informational',
              source: 'Cert Spotter (fallback)',
              checkId: 'ct',
              evidence: { 'CT entries found': String(fallbackEntries) },
            },
          ],
        };

        // Cache successful fallback result
        if (ctCache.size >= MAX_CACHE_ENTRIES) {
          ctCache.delete(ctCache.keys().next().value);
        }
        ctCache.set(queryDomain, { result, expiresAt: Date.now() + CT_CACHE_TTL_MS });

        return result;
      }
    } catch {
      // Fallback failed
    } finally {
      clearTimeout(fallbackTimer);
    }
  }

  // 3. Both failed -> status "error", failures are NEVER cached
  return {
    id: 'ct',
    name: 'Certificate Transparency',
    source: 'crt.sh',
    status: 'error',
    detail: 'Certificate Transparency providers unavailable. Not treated as a clean result.',
    entries: 0,
    findings: [],
  };
}
