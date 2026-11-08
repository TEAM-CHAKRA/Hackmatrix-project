import { env } from '../../config/env.js';

const URLHAUS_ENDPOINT = 'https://urlhaus-api.abuse.ch/v1/url/';

/**
 * Perform abuse.ch URLhaus database query
 * 
 * @param {object} params
 * @param {string} params.url
 * @param {Function} [params.fetchFn] Injectable fetch for testing
 * @returns {Promise<{
 *   id: 'urlhaus',
 *   name: 'URLhaus',
 *   source: 'URLhaus',
 *   status: 'completed' | 'no_match' | 'match_found' | 'unavailable' | 'error',
 *   detail?: string,
 *   findings: Array<object>
 * }>}
 */
export async function checkUrlhaus({ url, fetchFn = globalThis.fetch }) {
  // Scrub query params for privacy before query
  let cleanUrl = url;
  try {
    const parsed = new URL(url);
    cleanUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    // Keep as is if unparseable
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  if (env.URLHAUS_API_KEY) {
    headers['Auth-Key'] = env.URLHAUS_API_KEY;
  }

  try {
    const res = await fetchFn(URLHAUS_ENDPOINT, {
      method: 'POST',
      headers,
      body: new URLSearchParams({ url: cleanUrl }).toString(),
      signal: controller.signal,
    });

    if (!res.ok) {
      return {
        id: 'urlhaus',
        name: 'URLhaus',
        source: 'URLhaus',
        status: 'error',
        detail: `Provider returned HTTP ${res.status}`,
        findings: [],
      };
    }

    const data = await res.json();

    if (data.query_status === 'ok') {
      const threatType = data.threat || data.url_status || 'Malicious URL';
      return {
        id: 'urlhaus',
        name: 'URLhaus',
        source: 'URLhaus',
        status: 'match_found',
        detail: threatType,
        findings: [
          {
            id: 'f_urlhaus_match',
            title: `URLhaus threat match: ${threatType}`,
            description: `URLhaus lists this target as an active or reported threat (${threatType}).`,
            severity: 'critical',
            category: 'confirmed',
            source: 'URLhaus',
            checkId: 'urlhaus',
            evidence: {
              'Threat type': threatType,
              'URL status': data.url_status || 'unknown',
              'Reporter': data.reporter || 'community',
            },
          },
        ],
      };
    }

    if (data.query_status === 'no_results') {
      return {
        id: 'urlhaus',
        name: 'URLhaus',
        source: 'URLhaus',
        status: 'no_match',
        findings: [
          {
            id: 'f_urlhaus_clean',
            title: 'No threat intelligence match (URLhaus)',
            description: 'URLhaus database returned no match for this URL.',
            severity: 'info',
            category: 'informational',
            source: 'URLhaus',
            checkId: 'urlhaus',
            evidence: { 'URLhaus': 'No match' },
          },
        ],
      };
    }

    // Any other query_status (e.g. invalid_url, unknown_auth_key) is NOT a clean
    // result: report it as an error so it never counts toward coverage.
    return {
      id: 'urlhaus',
      name: 'URLhaus',
      source: 'URLhaus',
      status: 'error',
      detail: `Provider could not check this URL (${String(data.query_status || 'unknown response').slice(0, 40)})`,
      findings: [],
    };
  } catch (err) {
    const isTimeout = err.name === 'AbortError' || err.code === 'ETIMEDOUT';
    return {
      id: 'urlhaus',
      name: 'URLhaus',
      source: 'URLhaus',
      status: isTimeout ? 'unavailable' : 'error',
      detail: isTimeout ? 'Provider request timed out' : 'Provider connection error',
      findings: [],
    };
  } finally {
    clearTimeout(timer);
  }
}

