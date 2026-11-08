import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { validateTargetUrl, resolveAndValidate, SsrfError } from './ssrfValidator.js';
import { ERROR_CODES } from '../config/constants.js';

const SENSITIVE_QUERY_KEYS = [
  'token',
  'session',
  'auth',
  'key',
  'password',
  'code',
  'sig',
  'signature',
  'secret',
  'apikey',
];

/**
 * Case-insensitively redact sensitive query parameter values in a URL.
 * e.g. https://example.com/?token=secret -> https://example.com/?token=[redacted]
 */
export function redactSensitiveQueryParams(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    let modified = false;

    for (const key of Array.from(parsed.searchParams.keys())) {
      const lower = key.toLowerCase();
      if (SENSITIVE_QUERY_KEYS.some((k) => lower === k || lower.includes(k))) {
        parsed.searchParams.set(key, '[redacted]');
        modified = true;
      }
    }

    return modified ? parsed.toString() : rawUrl;
  } catch {
    return rawUrl;
  }
}

/**
 * Compare registrable domains (last two labels)
 */
function isDifferentRegistrableDomain(fromHost, toHost) {
  const fromParts = fromHost.toLowerCase().split('.');
  const toParts = toHost.toLowerCase().split('.');
  const fromDomain = fromParts.slice(-2).join('.');
  const toDomain = toParts.slice(-2).join('.');
  return fromDomain !== toDomain;
}

/**
 * Create pinned HTTP/HTTPS agent with custom single-resolve lookup
 */
function createPinnedAgent({ isHttps, validatedIp, family, timeoutMs }) {
  const agentOptions = {
    keepAlive: false,
    autoSelectFamily: false,
    timeout: timeoutMs,
    lookup: (hostname, options, callback) => {
      // Support options.all === true by returning [{ address, family }]
      if (options && options.all) {
        return callback(null, [{ address: validatedIp, family }]);
      }
      return callback(null, validatedIp, family);
    },
  };

  return isHttps ? new https.Agent(agentOptions) : new http.Agent(agentOptions);
}

/**
 * Single hop request execution using pinned agent
 */
function executeSingleHop({
  parsedUrl,
  validatedIp,
  family,
  method,
  timeoutMs,
  maxBytes,
  portOverride,
}) {
  return new Promise((resolve, reject) => {
    const isHttps = parsedUrl.protocol === 'https:';
    const lib = isHttps ? https : http;
    const agent = createPinnedAgent({ isHttps, validatedIp, family, timeoutMs });

    const port = portOverride || parsedUrl.port || (isHttps ? 443 : 80);

    const requestOptions = {
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      port,
      path: `${parsedUrl.pathname}${parsedUrl.search}`,
      method,
      agent,
      headers: {
        'User-Agent': 'CyberLens-Scanner/1.0',
        Accept: '*/*',
        Host: parsedUrl.host,
      },
      timeout: timeoutMs,
    };

    if (isHttps && !net.isIP(parsedUrl.hostname)) {
      // SNI servername (RFC 6066: literal IPv4 and IPv6 addresses are not permitted in "HostName")
      requestOptions.servername = parsedUrl.hostname;
    }

    const req = lib.request(requestOptions, (res) => {
      let totalBytes = 0;
      let truncated = false;
      const snippetChunks = [];
      const MAX_SNIPPET_BYTES = 4096; // keep small snippet

      res.on('data', (chunk) => {
        totalBytes += chunk.length;

        if (snippetChunks.length < MAX_SNIPPET_BYTES) {
          snippetChunks.push(chunk);
        }

        if (totalBytes > maxBytes) {
          truncated = true;
          req.destroy();
          cleanup();
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            bodySnippet: Buffer.concat(snippetChunks).slice(0, MAX_SNIPPET_BYTES).toString('utf-8'),
            truncated: true,
          });
        }
      });

      res.on('end', () => {
        cleanup();
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          bodySnippet: Buffer.concat(snippetChunks).slice(0, MAX_SNIPPET_BYTES).toString('utf-8'),
          truncated,
        });
      });

      res.on('error', (err) => {
        cleanup();
        reject(err);
      });
    });

    function cleanup() {
      agent.destroy();
    }

    req.on('timeout', () => {
      req.destroy();
      cleanup();
      const err = new Error(`Request timed out after ${timeoutMs}ms`);
      err.code = 'ETIMEDOUT';
      reject(err);
    });

    req.on('error', (err) => {
      cleanup();
      reject(err);
    });

    req.end();
  });
}

/**
 * Pinned safe HTTP client following redirects (up to maxRedirects)
 * - Single DNS resolve per hop
 * - Custom lookup pinning to validated IP
 * - Enforces port 80/443 and SSRF validation on every redirect
 * - Redacts sensitive query parameters in redirectChain
 * 
 * @param {string} url 
 * @param {object} options 
 * @returns {Promise<{
 *   finalUrl: string,
 *   statusCode: number,
 *   headers: Record<string, any>,
 *   redirectChain: Array<{ url: string, statusCode: number, suspicious: boolean, note?: string }>,
 *   bodySnippet: string,
 *   truncated: boolean
 * }>}
 */
export async function safeRequest(url, {
  method = 'GET',
  timeoutMs = 8000,
  maxBytes = 1048576,
  maxRedirects = 5,
  resolver,
  preValidatedIp,
  preValidatedFamily,
  _dangerouslyAllowLocalhostForTesting = false,
  _portOverrideForTesting,
} = {}) {
  const redirectChain = [];
  const visitedUrls = new Set();
  let currentUrlStr = url;
  let hops = 0;

  // Localhost bypass is strictly prohibited in production
  const allowLocalhost = process.env.NODE_ENV !== 'production' && _dangerouslyAllowLocalhostForTesting;

  while (hops <= maxRedirects) {
    const redactedCurrentUrl = redactSensitiveQueryParams(currentUrlStr);

    // Redirect loop detection
    if (visitedUrls.has(currentUrlStr)) {
      throw new SsrfError(`Redirect loop detected at ${redactedCurrentUrl}`, {
        code: ERROR_CODES.VALIDATION_ERROR,
        status: 400,
      });
    }
    visitedUrls.add(currentUrlStr);

    // 1. Validate target URL
    const { parsed, port } = validateTargetUrl(currentUrlStr);

    // 2. Resolve target ONCE and validate IP (skip DNS resolve on first hop if preValidatedIp provided)
    let validatedIp;
    let family;

    if (hops === 0 && preValidatedIp) {
      validatedIp = preValidatedIp;
      family = preValidatedFamily || (net.isIPv6(preValidatedIp) ? 6 : 4);
    } else {
      const resolved = await resolveAndValidate(parsed.hostname, {
        resolver,
        _dangerouslyAllowLocalhostForTesting: allowLocalhost,
      });
      validatedIp = resolved.ip;
      family = resolved.family;
    }

    // 3. Execute pinned single hop
    const response = await executeSingleHop({
      parsedUrl: parsed,
      validatedIp,
      family,
      method,
      timeoutMs,
      maxBytes,
      portOverride: allowLocalhost ? _portOverrideForTesting : undefined,
    });

    const { statusCode, headers, bodySnippet, truncated } = response;
    const isRedirect = [301, 302, 303, 307, 308].includes(statusCode) && headers.location;

    if (!isRedirect) {
      // Terminal destination reached
      redirectChain.push({
        url: redactedCurrentUrl,
        statusCode,
        suspicious: false,
      });

      return {
        finalUrl: redactedCurrentUrl,
        statusCode,
        headers,
        redirectChain,
        bodySnippet,
        truncated,
      };
    }

    // 4. Handle redirect hop
    hops++;
    if (hops > maxRedirects) {
      throw new SsrfError(`Maximum redirect limit of ${maxRedirects} hops exceeded.`, {
        code: ERROR_CODES.VALIDATION_ERROR,
        status: 400,
      });
    }

    let nextParsed;
    try {
      nextParsed = new URL(headers.location, currentUrlStr);
    } catch {
      throw new SsrfError(`Invalid redirect Location header: ${headers.location}`, {
        code: ERROR_CODES.VALIDATION_ERROR,
        status: 400,
      });
    }

    // Determine if redirect is suspicious
    let suspicious = false;
    let note;

    if (parsed.protocol === 'https:' && nextParsed.protocol === 'http:') {
      suspicious = true;
      note = 'Redirect downgraded connection from HTTPS to HTTP.';
    } else if (isDifferentRegistrableDomain(parsed.hostname, nextParsed.hostname)) {
      suspicious = true;
      note = `Redirected to external domain (${nextParsed.hostname}).`;
    }

    redirectChain.push({
      url: redactedCurrentUrl,
      statusCode,
      suspicious,
      note,
    });

    currentUrlStr = nextParsed.toString();
  }

  throw new SsrfError(`Maximum redirect limit of ${maxRedirects} hops exceeded.`, {
    code: ERROR_CODES.VALIDATION_ERROR,
    status: 400,
  });
}

