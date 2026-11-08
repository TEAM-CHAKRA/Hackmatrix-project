import dns from 'node:dns/promises';
import net from 'node:net';
import { ERROR_CODES } from '../config/constants.js';
import { AppError } from '../utils/response.js';

/**
 * Typed SSRF error that integrates with the existing errorHandler
 * Envelope: { success: false, error: { code: 'SSRF_BLOCKED' | 'VALIDATION_ERROR', message, details } }
 */
export class SsrfError extends AppError {
  constructor(message, { code = ERROR_CODES.SSRF_BLOCKED, status = 400, details = {} } = {}) {
    super(message, { code, status, details });
    this.name = 'SsrfError';
  }
}

// ---------------------------------------------------------------------------
// BlockList setup for IPv4 and IPv6
// ---------------------------------------------------------------------------

const ipv4BlockList = new net.BlockList();
ipv4BlockList.addSubnet('0.0.0.0', 8);        // Current network
ipv4BlockList.addSubnet('10.0.0.0', 8);       // Private (RFC 1918)
ipv4BlockList.addSubnet('100.64.0.0', 10);    // Carrier-grade NAT (RFC 6598)
ipv4BlockList.addSubnet('127.0.0.0', 8);      // Loopback
ipv4BlockList.addSubnet('169.254.0.0', 16);   // Link-local / Cloud metadata (169.254.169.254)
ipv4BlockList.addSubnet('172.16.0.0', 12);    // Private (RFC 1918)
ipv4BlockList.addSubnet('192.0.0.0', 24);     // IETF protocol assignments
ipv4BlockList.addSubnet('192.0.2.0', 24);     // TEST-NET-1
ipv4BlockList.addSubnet('192.88.99.0', 24);   // 6to4 relay anycast
ipv4BlockList.addSubnet('192.168.0.0', 16);   // Private (RFC 1918)
ipv4BlockList.addSubnet('198.18.0.0', 15);    // Network benchmark
ipv4BlockList.addSubnet('198.51.100.0', 24);  // TEST-NET-2
ipv4BlockList.addSubnet('203.0.113.0', 24);   // TEST-NET-3
ipv4BlockList.addSubnet('224.0.0.0', 4);      // Multicast
ipv4BlockList.addSubnet('240.0.0.0', 4);      // Reserved
ipv4BlockList.addAddress('255.255.255.255');  // Broadcast

const ipv6BlockList = new net.BlockList();
ipv6BlockList.addAddress('::', 'ipv6');       // Unspecified
ipv6BlockList.addAddress('::1', 'ipv6');      // Loopback
ipv6BlockList.addSubnet('fc00::', 7, 'ipv6'); // Unique local address (ULA)
ipv6BlockList.addSubnet('fe80::', 10, 'ipv6');// Link-local
ipv6BlockList.addSubnet('64:ff9b::', 96, 'ipv6'); // IPv4/IPv6 translation (RFC 6052)
ipv6BlockList.addSubnet('2001:db8::', 32, 'ipv6'); // Documentation
ipv6BlockList.addSubnet('2001::', 32, 'ipv6');     // Teredo prefix (RFC 4380)
ipv6BlockList.addSubnet('2002::', 16, 'ipv6');     // 6to4 prefix (RFC 3056)
ipv6BlockList.addSubnet('ff00::', 8, 'ipv6'); // Multicast

/**
 * Extract embedded IPv4 from an IPv4-mapped IPv6 address (::ffff:x.x.x.x or ::ffff:hex:hex)
 */
function extractEmbeddedIpv4(ipv6Str) {
  const norm = ipv6Str.toLowerCase().trim();
  if (!norm.startsWith('::ffff:')) return null;

  const rest = norm.slice(7);
  // Dotted decimal representation: e.g. ::ffff:127.0.0.1
  if (net.isIPv4(rest)) {
    return rest;
  }

  // Hexadecimal group representation: e.g. ::ffff:7f00:1
  const parts = rest.split(':');
  if (parts.length === 2 && parts.every((p) => /^[0-9a-f]{1,4}$/i.test(p))) {
    const high = parseInt(parts[0], 16);
    const low = parseInt(parts[1], 16);
    const b1 = (high >> 8) & 0xff;
    const b2 = high & 0xff;
    const b3 = (low >> 8) & 0xff;
    const b4 = low & 0xff;
    return `${b1}.${b2}.${b3}.${b4}`;
  }

  return null;
}

/**
 * Check whether an IP (v4 or v6) is forbidden
 */
export function isForbiddenIp(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const trimmed = ip.trim().replace(/^\[|\]$/g, '');

  if (net.isIPv4(trimmed)) {
    return ipv4BlockList.check(trimmed, 'ipv4');
  }

  if (net.isIPv6(trimmed)) {
    // Check IPv4-mapped IPv6 (::ffff:0:0/96)
    if (trimmed.toLowerCase().startsWith('::ffff:')) {
      const embeddedIpv4 = extractEmbeddedIpv4(trimmed);
      if (embeddedIpv4) {
        return ipv4BlockList.check(embeddedIpv4, 'ipv4');
      }
      return true; // Any unparseable ::ffff: address is blocked
    }

    return ipv6BlockList.check(trimmed, 'ipv6');
  }

  // Not a valid IP string
  return true;
}

/**
 * Detect raw host strings with unusual IP encodings (pure decimal, hex, or octal notation)
 */
function hasUnusualIpEncoding(rawHost) {
  const cleaned = rawHost.replace(/^\[|\]$/g, '').trim();

  // Purely numeric (e.g. 2130706433 or 127.1)
  if (/^\d+$/.test(cleaned)) {
    return true;
  }

  // Hexadecimal notation (e.g. 0x7f.0.0.1 or 0x7f000001)
  if (/0x[0-9a-f]+/i.test(cleaned)) {
    return true;
  }

  // Octal notation (leading zeros, e.g. 0177.0.0.1)
  const parts = cleaned.split('.');
  if (parts.length > 1 && parts.every((p) => /^\d+$/.test(p))) {
    if (parts.some((p) => p.length > 1 && p.startsWith('0'))) {
      return true;
    }
    // Partial IP / dword forms (e.g. 127.1)
    if (parts.length < 4) {
      return true;
    }
  }

  return false;
}

/**
 * Extract raw host portion from input URL string prior to WHATWG parser normalization
 */
function extractRawHost(input) {
  const match = input.match(/^[a-z0-9+.-]+:\/\/([^/?#]+)/i);
  if (!match) return '';
  let hostPart = match[1];
  // Strip userinfo if present
  if (hostPart.includes('@')) {
    hostPart = hostPart.split('@')[1];
  }
  // Strip port if present
  if (hostPart.startsWith('[')) {
    const bracketEnd = hostPart.indexOf(']');
    return bracketEnd !== -1 ? hostPart.slice(0, bracketEnd + 1) : hostPart;
  }
  return hostPart.split(':')[0];
}

/**
 * Validate target URL according to strict Phase 2 SSRF rules:
 * - Length <= 2048
 * - Allowed protocols: http: and https: only
 * - Ports: 80 and 443 only (any other explicit port rejected)
 * - Credentials (user:pass@) rejected
 * - Empty hostname rejected
 * - Raw numeric/hex/octal encodings rejected
 * - Parsed hostname checked against forbidden IPs
 * 
 * @param {string} input 
 * @returns {{ parsed: URL, port: number, isHttps: boolean }}
 */
export function validateTargetUrl(input) {
  if (typeof input !== 'string' || !input.trim()) {
    throw new SsrfError('Target URL must be a non-empty string.', {
      code: ERROR_CODES.VALIDATION_ERROR,
      status: 400,
    });
  }

  if (input.length > 2048) {
    throw new SsrfError('Target URL exceeds maximum allowed length of 2048 characters.', {
      code: ERROR_CODES.VALIDATION_ERROR,
      status: 400,
    });
  }

  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    throw new SsrfError('The target could not be parsed as a valid URL.', {
      code: ERROR_CODES.VALIDATION_ERROR,
      status: 400,
    });
  }

  // Protocol check: only http: and https: allowed
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new SsrfError(`Protocol '${parsed.protocol}' is not allowed. Only HTTP and HTTPS are permitted.`, {
      code: ERROR_CODES.VALIDATION_ERROR,
      status: 400,
    });
  }

  // Reject credentials in URL
  if (parsed.username || parsed.password) {
    throw new SsrfError('URLs containing embedded credentials (user:pass@) are prohibited.', {
      code: ERROR_CODES.VALIDATION_ERROR,
      status: 400,
    });
  }

  // Reject empty hostname
  if (!parsed.hostname) {
    throw new SsrfError('Target URL hostname cannot be empty.', {
      code: ERROR_CODES.VALIDATION_ERROR,
      status: 400,
    });
  }

  // Enforce ports 80 and 443 only
  const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;
  if (port !== 80 && port !== 443) {
    throw new SsrfError(`Port ${port} is restricted. Only ports 80 and 443 are permitted.`, {
      code: ERROR_CODES.SSRF_BLOCKED,
      status: 400,
    });
  }

  // Check raw input host for unusual IP encodings (decimal, octal, hex)
  const rawHost = extractRawHost(input);
  if (hasUnusualIpEncoding(rawHost)) {
    throw new SsrfError('Hostnames with non-standard numeric, octal, or hex IP representations are blocked.', {
      code: ERROR_CODES.SSRF_BLOCKED,
      status: 400,
    });
  }

  // Validate the WHATWG-normalized parsed hostname if it is an IP literal
  const parsedHost = parsed.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(parsedHost) && isForbiddenIp(parsedHost)) {
    throw new SsrfError(`Target IP address '${parsedHost}' is a restricted or private address.`, {
      code: ERROR_CODES.SSRF_BLOCKED,
      status: 400,
    });
  }

  return {
    parsed,
    port,
    isHttps: parsed.protocol === 'https:',
  };
}

/**
 * Resolve target hostname ONCE, validate every returned address, and return pinned connection details.
 * 
 * @param {string} hostname 
 * @param {object} options
 * @param {Function} [options.resolver] Injectable DNS resolver for testing
 * @param {boolean} [options._dangerouslyAllowLocalhostForTesting] Test-only bypass, disabled in production
 * @returns {Promise<{ ip: string, family: number, addresses: string[] }>}
 */
export async function resolveAndValidate(hostname, {
  resolver = dns.lookup,
  _dangerouslyAllowLocalhostForTesting = false,
} = {}) {
  // Strictly disallow test bypass in production environment
  const allowLocalhost = process.env.NODE_ENV !== 'production' && _dangerouslyAllowLocalhostForTesting;
  const cleanHost = hostname.replace(/^\[|\]$/g, '').trim();

  // 1. IP literal: skip DNS lookup entirely
  if (net.isIP(cleanHost)) {
    if (isForbiddenIp(cleanHost) && !allowLocalhost) {
      throw new SsrfError(`Target address '${cleanHost}' is a restricted or private address.`, {
        code: ERROR_CODES.SSRF_BLOCKED,
        status: 400,
      });
    }
    return {
      ip: cleanHost,
      family: net.isIPv6(cleanHost) ? 6 : 4,
      addresses: [cleanHost],
    };
  }

  // 2. Hostname: resolve ONCE using resolver
  let result;
  try {
    result = await resolver(cleanHost, { all: true });
  } catch (err) {
    const error = new SsrfError(`We couldn't find the website '${cleanHost}' (its address did not resolve). Check the link and try again.`, {
      code: ERROR_CODES.VALIDATION_ERROR,
      status: 400,
    });
    error.original = err;
    throw error;
  }

  const rawAddresses = Array.isArray(result) ? result : [result];
  if (!rawAddresses || rawAddresses.length === 0) {
    throw new SsrfError(`No IP addresses returned for host '${cleanHost}'.`, {
      code: ERROR_CODES.VALIDATION_ERROR,
      status: 400,
    });
  }

  const addressRecords = rawAddresses.map((r) => {
    if (typeof r === 'string') {
      return { address: r, family: net.isIPv6(r) ? 6 : 4 };
    }
    return { address: r.address, family: r.family || (net.isIPv6(r.address) ? 6 : 4) };
  });

  const allIps = addressRecords.map((r) => r.address);

  // Validate EVERY resolved IP address against forbidden ranges
  for (const record of addressRecords) {
    const ip = record.address;
    if (isForbiddenIp(ip) && !allowLocalhost) {
      throw new SsrfError(`Target host '${cleanHost}' resolved to restricted address ${ip}.`, {
        code: ERROR_CODES.SSRF_BLOCKED,
        status: 400,
      });
    }
  }

  // Pick primary connection address (prefer IPv4)
  const primary = addressRecords.find((r) => r.family === 4) || addressRecords[0];

  return {
    ip: primary.address,
    family: primary.family,
    addresses: allIps,
  };
}

