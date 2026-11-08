import { safeRequest } from './safeHttpClient.js';

const RECOMMENDED_HEADERS = [
  {
    name: 'Strict-Transport-Security',
    recommendation: 'Enable HSTS with max-age of at least 31536000 (1 year) and includeSubDomains.',
    severity: 'low',
  },
  {
    name: 'Content-Security-Policy',
    recommendation: 'Define a restrictive CSP to prevent cross-site scripting (XSS) and data injection.',
    severity: 'low',
  },
  {
    name: 'X-Frame-Options',
    recommendation: 'Set DENY or SAMEORIGIN to prevent clickjacking in framing contexts.',
    severity: 'low',
  },
  {
    name: 'X-Content-Type-Options',
    recommendation: 'Set to "nosniff" to prevent MIME-type sniffing.',
    severity: 'low',
  },
  {
    name: 'Referrer-Policy',
    recommendation: 'Set "strict-origin-when-cross-origin" to protect sensitive URL paths in referrals.',
    severity: 'low',
  },
];

/**
 * Parse Set-Cookie headers into structured cookie objects
 */
function parseCookies(cookieHeaders = []) {
  const headers = Array.isArray(cookieHeaders) ? cookieHeaders : [cookieHeaders].filter(Boolean);
  const cookies = [];

  for (const raw of headers) {
    if (!raw) continue;
    const parts = raw.split(';').map((p) => p.trim());
    const [nameVal] = parts;
    const [name] = nameVal.split('=');

    const lowerParts = parts.map((p) => p.toLowerCase());
    const secure = lowerParts.includes('secure');
    const httpOnly = lowerParts.includes('httponly');
    const sameSitePart = parts.find((p) => p.toLowerCase().startsWith('samesite='));
    const sameSite = sameSitePart ? sameSitePart.split('=')[1] : null;

    cookies.push({
      name: name.trim(),
      secure,
      httpOnly,
      sameSite,
    });
  }

  return cookies;
}

/**
 * Inspect HTTP security headers and cookies
 * 
 * @param {object} params
 * @param {string} params.url
 * @param {string} params.preValidatedIp
 * @param {number} params.preValidatedFamily
 * @param {Function} [params.resolver]
 * @param {boolean} [params._dangerouslyAllowLocalhostForTesting]
 * @param {number} [params._portOverrideForTesting]
 * @returns {Promise<{
 *   id: 'headers',
 *   name: 'HTTP security headers',
 *   source: 'HTTP security header inspection',
 *   status: 'completed' | 'unavailable' | 'error',
 *   securityHeaders: object,
 *   redirectChain: Array<object>,
 *   findings: Array<object>
 * }>}
 */
export async function inspectHeaders({
  url,
  preValidatedIp,
  preValidatedFamily,
  resolver,
  requestFn = safeRequest,
  _dangerouslyAllowLocalhostForTesting = false,
  _portOverrideForTesting,
}) {
  const findings = [];

  try {
    const res = await requestFn(url, {
      method: 'GET',
      timeoutMs: 6000,
      maxBytes: 32768, // only need headers and start of body
      resolver,
      preValidatedIp,
      preValidatedFamily,
      _dangerouslyAllowLocalhostForTesting,
      _portOverrideForTesting,
    });

    const headersMap = res.headers || {};
    const headerResults = [];

    for (const rec of RECOMMENDED_HEADERS) {
      const headerVal = headersMap[rec.name.toLowerCase()];
      const isPresent = Boolean(headerVal);

      headerResults.push({
        name: rec.name,
        present: isPresent,
        value: isPresent ? String(headerVal) : undefined,
        recommendation: rec.recommendation,
      });

      if (!isPresent) {
        findings.push({
          id: `f_header_${rec.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}`,
          title: `${rec.name} header missing`,
          description: `The website did not return the ${rec.name} security header. ${rec.recommendation}`,
          severity: rec.severity,
          category: 'weakness',
          source: 'HTTP security header inspection',
          checkId: 'headers',
          evidence: { Header: rec.name, Observed: 'Not present' },
        });
      }
    }

    const cookies = parseCookies(headersMap['set-cookie']);

    // Check insecure cookies
    for (const cookie of cookies) {
      if (!cookie.secure) {
        findings.push({
          id: `f_cookie_insecure_${cookie.name}`,
          title: `Cookie "${cookie.name}" missing Secure flag`,
          description: `The cookie "${cookie.name}" was set without the Secure attribute, allowing it to be transmitted over unencrypted HTTP.`,
          severity: 'low',
          category: 'weakness',
          source: 'HTTP security header inspection',
          checkId: 'headers',
          evidence: { Cookie: cookie.name, Secure: 'No' },
        });
      }
    }

    // HTTPS redirect check from redirectChain
    let httpsRedirect = null;
    if (res.redirectChain && res.redirectChain.length > 1) {
      const firstHop = res.redirectChain[0];
      const lastHop = res.redirectChain[res.redirectChain.length - 1];
      if (firstHop.url.startsWith('http://') && lastHop.url.startsWith('https://')) {
        httpsRedirect = true;
      } else if (firstHop.url.startsWith('http://') && lastHop.url.startsWith('http://')) {
        httpsRedirect = false;
      }
    }

    return {
      id: 'headers',
      name: 'HTTP security headers',
      source: 'HTTP security header inspection',
      status: 'completed',
      securityHeaders: {
        status: 'completed',
        httpsRedirect,
        headers: headerResults,
        cookies,
      },
      redirectChain: res.redirectChain,
      findings,
    };
  } catch (err) {
    return {
      id: 'headers',
      name: 'HTTP security headers',
      source: 'HTTP security header inspection',
      status: 'unavailable',
      detail: `Host unreachable: ${err.message}`,
      securityHeaders: {
        status: 'unavailable',
        note: `Host unreachable (${err.message}) — headers could not be inspected.`,
        headers: [],
        cookies: [],
      },
      redirectChain: [{ url, statusCode: null, suspicious: false, note: err.message }],
      findings: [],
    };
  }
}
