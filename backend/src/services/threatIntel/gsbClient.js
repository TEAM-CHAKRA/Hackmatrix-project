import { env } from '../../config/env.js';

const GSB_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

/**
 * Perform Google Safe Browsing Lookup v4
 * 
 * @param {object} params
 * @param {string} params.url
 * @param {Function} [params.fetchFn] Injectable fetch for testing
 * @returns {Promise<{
 *   id: 'gsb',
 *   name: 'Google Safe Browsing',
 *   source: 'Google Safe Browsing',
 *   status: 'completed' | 'no_match' | 'match_found' | 'unavailable' | 'error',
 *   detail?: string,
 *   findings: Array<object>
 * }>}
 */
export async function checkGoogleSafeBrowsing({ url, fetchFn = globalThis.fetch }) {
  const apiKey = env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (!apiKey) {
    return {
      id: 'gsb',
      name: 'Google Safe Browsing',
      source: 'Google Safe Browsing',
      status: 'unavailable',
      detail: 'not configured',
      findings: [],
    };
  }

  // Scrub query params for privacy before external API query
  let cleanUrl = url;
  try {
    const parsed = new URL(url);
    cleanUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    // Keep as is if unparseable
  }

  const payload = {
    client: {
      clientId: 'cyberlens-platform',
      clientVersion: '1.0.0',
    },
    threatInfo: {
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION',
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url: cleanUrl }],
    },
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);

  try {
    const res = await fetchFn(`${GSB_ENDPOINT}?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    if (!res.ok) {
      return {
        id: 'gsb',
        name: 'Google Safe Browsing',
        source: 'Google Safe Browsing',
        status: 'error',
        detail: `Provider returned HTTP ${res.status}`,
        findings: [],
      };
    }

    const data = await res.json();
    const matches = data.matches || [];

    if (matches.length > 0) {
      const threatTypes = Array.from(new Set(matches.map((m) => m.threatType))).join(', ');
      return {
        id: 'gsb',
        name: 'Google Safe Browsing',
        source: 'Google Safe Browsing',
        status: 'match_found',
        detail: threatTypes,
        findings: matches.map((m, idx) => ({
          id: `f_gsb_${idx + 1}`,
          title: `Google Safe Browsing: ${m.threatType}`,
          description: `Google Safe Browsing lists this URL under the ${m.threatType} threat type.`,
          severity: 'critical',
          category: 'confirmed',
          source: 'Google Safe Browsing',
          checkId: 'gsb',
          evidence: {
            'Threat type': m.threatType,
            Platform: m.platformType || 'ANY_PLATFORM',
            Match: 'Exact URL',
          },
        })),
      };
    }

    return {
      id: 'gsb',
      name: 'Google Safe Browsing',
      source: 'Google Safe Browsing',
      status: 'no_match',
      findings: [
        {
          id: 'f_gsb_clean',
          title: 'No threat intelligence match (Google Safe Browsing)',
          description: 'Google Safe Browsing returned no threat match for this URL.',
          severity: 'info',
          category: 'informational',
          source: 'Google Safe Browsing',
          checkId: 'gsb',
          evidence: { 'Google Safe Browsing': 'No match' },
        },
      ],
    };
  } catch (err) {
    const isTimeout = err.name === 'AbortError' || err.code === 'ETIMEDOUT';
    return {
      id: 'gsb',
      name: 'Google Safe Browsing',
      source: 'Google Safe Browsing',
      status: isTimeout ? 'unavailable' : 'error',
      detail: isTimeout ? 'Provider request timed out' : 'Provider connection error',
      findings: [],
    };
  } finally {
    clearTimeout(timer);
  }
}

