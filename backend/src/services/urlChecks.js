import net from 'node:net';
import { validateTargetUrl, resolveAndValidate } from './ssrfValidator.js';
import { checkGoogleSafeBrowsing } from './threatIntel/gsbClient.js';
import { checkUrlhaus } from './threatIntel/urlhausClient.js';
import { analyzeDomain } from './domainAnalyzer.js';
import { inspectTls } from './tlsInspector.js';
import { checkCertificateTransparency } from './ctService.js';
import { inspectHeaders } from './headersInspector.js';
import { URL_CHECK_IDS } from '../config/constants.js';

const CHECK_METADATA = {
  gsb: { name: 'Google Safe Browsing', source: 'Google Safe Browsing' },
  urlhaus: { name: 'URLhaus', source: 'URLhaus' },
  domain: { name: 'Domain and brand analysis', source: 'Domain analysis' },
  tls: { name: 'TLS inspection', source: 'TLS inspection' },
  ct: { name: 'Certificate Transparency', source: 'crt.sh' },
  headers: { name: 'HTTP security headers', source: 'HTTP security header inspection' },
};

/**
 * Run the 6 core URL investigation checks in parallel (Promise.allSettled)
 * Resolves DNS ONCE, passes pre-validated IP to downstream network checks.
 * Always returns exactly 6 checks in fixed order: [gsb, urlhaus, domain, tls, ct, headers].
 * 
 * @param {object} params
 * @param {string} params.url
 * @param {Function} [params.resolver] Optional injectable DNS resolver for testing
 * @param {Function} [params.fetchFn] Optional injectable fetch function for mock tests
 * @param {string} [params.preValidatedIp] Optional pre-validated IP to skip re-resolving
 * @param {number} [params.preValidatedFamily] Optional IP family (4 or 6)
 * @param {string[]} [params.preValidatedAddresses] Optional list of all validated IPs
 * @param {Function} [params.onCheckComplete] Optional callback called whenever an individual check finishes
 * @param {boolean} [params._dangerouslyAllowLocalhostForTesting=false]
 * @param {number} [params._portOverrideForTesting]
 * @returns {Promise<{
 *   target: { display: string, host: string },
 *   resolvedIp: string,
 *   allIps: string[],
 *   checks: Array<{ id: string, name: string, source: string, status: string, detail?: string }>,
 *   tls: object,
 *   securityHeaders: object,
 *   redirectChain: Array<object>,
 *   domainAnalysis: object,
 *   findings: Array<object>
 * }>}
 */
export async function runUrlChecks({
  url,
  resolver,
  fetchFn = globalThis.fetch,
  requestFn,
  tlsConnectFn,
  tlsTimeoutMs = 5000,
  preValidatedIp,
  preValidatedFamily,
  preValidatedAddresses,
  onCheckComplete,
  signal,
  _dangerouslyAllowLocalhostForTesting = false,
  _portOverrideForTesting,
}) {
  if (signal?.aborted) {
    throw new Error('Investigation was cancelled or timed out.');
  }

  // 1. Validate Target URL (protocols, ports, encodings)
  const { parsed, port, isHttps } = validateTargetUrl(url);
  const hostname = parsed.hostname;

  // 2. Resolve DNS ONCE per investigation (or reuse pre-validated IP from caller)
  let validatedIp = preValidatedIp;
  let family = preValidatedFamily;
  let addresses = preValidatedAddresses;

  if (!validatedIp) {
    const resolved = await resolveAndValidate(hostname, {
      resolver,
      _dangerouslyAllowLocalhostForTesting,
    });
    validatedIp = resolved.ip;
    family = resolved.family;
    addresses = resolved.addresses;
  } else if (!family) {
    family = net.isIP(validatedIp) === 6 ? 6 : 4;
    addresses = addresses || [validatedIp];
  }

  // Display URL with query string scrubbed for safety
  const displayUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;

  // Helper to notify check completion if callback is provided
  const notifyCheckComplete = (checkId, result, isError = false) => {
    if (signal?.aborted || typeof onCheckComplete !== 'function') return;
    const meta = CHECK_METADATA[checkId];
    try {
      if (isError) {
        onCheckComplete({
          id: checkId,
          name: meta.name,
          source: meta.source,
          status: 'error',
          detail: `Check threw an error: ${result?.message || 'Unknown failure'}`,
          findings: [],
        });
      } else {
        onCheckComplete({
          id: checkId,
          name: result?.name || meta.name,
          source: result?.source || meta.source,
          status: result?.status || 'completed',
          detail: result?.detail || undefined,
          findings: result?.findings || [],
        });
      }
    } catch {
      // onCheckComplete callback failure must never fail runUrlChecks
    }
  };

  // 3. Dispatch the 6 checks in parallel
  const gsbPromise = checkGoogleSafeBrowsing({ url, fetchFn })
    .then((val) => { notifyCheckComplete('gsb', val); return val; })
    .catch((err) => { notifyCheckComplete('gsb', err, true); throw err; });

  const urlhausPromise = checkUrlhaus({ url, fetchFn })
    .then((val) => { notifyCheckComplete('urlhaus', val); return val; })
    .catch((err) => { notifyCheckComplete('urlhaus', err, true); throw err; });

  const domainPromise = analyzeDomain({ hostname, fetchFn })
    .then((val) => { notifyCheckComplete('domain', val); return val; })
    .catch((err) => { notifyCheckComplete('domain', err, true); throw err; });

  const tlsPromise = inspectTls({
    hostname,
    validatedIp,
    isHttps,
    timeoutMs: tlsTimeoutMs,
    tlsConnectFn,
  })
    .then((val) => { notifyCheckComplete('tls', val); return val; })
    .catch((err) => { notifyCheckComplete('tls', err, true); throw err; });

  const ctPromise = checkCertificateTransparency({ hostname, fetchFn })
    .then((val) => { notifyCheckComplete('ct', val); return val; })
    .catch((err) => { notifyCheckComplete('ct', err, true); throw err; });

  const headersPromise = inspectHeaders({
    url,
    preValidatedIp: validatedIp,
    preValidatedFamily: family,
    resolver,
    requestFn,
    _dangerouslyAllowLocalhostForTesting,
    _portOverrideForTesting,
  })
    .then((val) => { notifyCheckComplete('headers', val); return val; })
    .catch((err) => { notifyCheckComplete('headers', err, true); throw err; });

  const settledResults = await Promise.allSettled([
    gsbPromise,
    urlhausPromise,
    domainPromise,
    tlsPromise,
    ctPromise,
    headersPromise,
  ]);

  // 4. Map results in fixed order: [gsb, urlhaus, domain, tls, ct, headers]
  const allFindings = [];
  const checks = [];

  settledResults.forEach((res, index) => {
    const checkId = URL_CHECK_IDS[index];
    const meta = CHECK_METADATA[checkId];

    if (res.status === 'fulfilled') {
      const val = res.value;
      checks.push({
        id: checkId,
        name: val.name || meta.name,
        source: val.source || meta.source,
        status: val.status || 'completed',
        detail: val.detail || undefined,
      });

      if (Array.isArray(val.findings)) {
        allFindings.push(...val.findings);
      }
    } else {
      // If a check threw an unexpected error, isolate failure to that check
      checks.push({
        id: checkId,
        name: meta.name,
        source: meta.source,
        status: 'error',
        detail: `Check threw an error: ${res.reason?.message || 'Unknown failure'}`,
      });
    }
  });

  // Extract individual subsystems payloads
  const domainResult = settledResults[2].status === 'fulfilled' ? settledResults[2].value : null;
  const tlsResult = settledResults[3].status === 'fulfilled' ? settledResults[3].value : null;
  const headersResult = settledResults[5].status === 'fulfilled' ? settledResults[5].value : null;

  if (signal?.aborted) {
    throw new Error('Investigation was cancelled or timed out.');
  }

  return {
    target: {
      display: displayUrl,
      host: hostname,
    },
    resolvedIp: validatedIp,
    allIps: addresses,
    checks,
    tls: tlsResult?.tls || { status: 'unavailable', httpsAvailable: false },
    securityHeaders: headersResult?.securityHeaders || { status: 'unavailable', headers: [], cookies: [] },
    redirectChain: headersResult?.redirectChain || [{ url: displayUrl, statusCode: null, suspicious: false }],
    domainAnalysis: domainResult?.extras || null,
    findings: allFindings,
  };
}
