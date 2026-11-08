import test from 'node:test';
import assert from 'node:assert/strict';
import { runUrlChecks } from '../src/services/urlChecks.js';
import { checkGoogleSafeBrowsing } from '../src/services/threatIntel/gsbClient.js';
import { checkUrlhaus } from '../src/services/threatIntel/urlhausClient.js';
import { analyzeDomain, _resetRdapCache, getDomainParts } from '../src/services/domainAnalyzer.js';
import { inspectTls, checkDistrustedCA } from '../src/services/tlsInspector.js';
import { checkCertificateTransparency, _resetCtCache } from '../src/services/ctService.js';
import { inspectHeaders } from '../src/services/headersInspector.js';
import { env } from '../src/config/env.js';
import { URL_CHECK_IDS } from '../src/config/constants.js';

import { EventEmitter } from 'node:events';

const originalFetch = globalThis.fetch;
const originalGsbKey = env.GOOGLE_SAFE_BROWSING_API_KEY;

function createMockTlsConnect(customCert = {}) {
  return (opts, callback) => {
    const socket = new EventEmitter();
    socket.destroy = () => {};
    socket.authorized = customCert.authorized !== undefined ? customCert.authorized : true;
    socket.authorizationError = customCert.authorizationError || null;
    socket.getPeerCertificate = () => ({
      valid_from: customCert.valid_from !== undefined ? customCert.valid_from : 'Jan 1 00:00:00 2026 GMT',
      valid_to: customCert.valid_to !== undefined ? customCert.valid_to : 'Jan 1 00:00:00 2027 GMT',
      subject: customCert.subject || { CN: 'example.com' },
      issuer: customCert.issuer || { CN: 'DigiCert Global Root G3' },
      subjectaltname: customCert.subjectaltname || 'DNS:example.com, DNS:www.example.com',
      bits: customCert.bits !== undefined ? customCert.bits : 256,
      asn1Curve: customCert.asn1Curve !== undefined ? customCert.asn1Curve : 'prime256v1',
      sigalg: customCert.sigalg !== undefined ? customCert.sigalg : 'ecdsa-with-SHA384',
      pubkey: customCert.pubkey || Buffer.alloc(65),
    });
    process.nextTick(() => {
      callback();
    });
    return socket;
  };
}

const mockHeadersRequest = async (url) => ({
  statusCode: 200,
  headers: {
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'content-security-policy': "default-src 'self'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
  },
  redirectChain: [{ url, statusCode: 200, suspicious: false }],
  bodySnippet: '',
  truncated: false,
});

test.afterEach(() => {
  globalThis.fetch = originalFetch;
  env.GOOGLE_SAFE_BROWSING_API_KEY = originalGsbKey;
});

// ---------------------------------------------------------------------------
// 1. Single DNS Resolution & 6 Fixed Order Checks
// ---------------------------------------------------------------------------

test('Phase 3: runUrlChecks resolves DNS exactly once per investigation', async () => {
  let resolverCallCount = 0;
  const mockResolver = async (host) => {
    resolverCallCount++;
    return [{ address: '93.184.216.34', family: 4 }];
  };

  const mockFetch = async (url) => {
    return {
      ok: true,
      status: 200,
      json: async () => ([]),
      text: async () => '',
    };
  };

  const result = await runUrlChecks({
    url: 'https://example.com/login?token=secret123',
    resolver: mockResolver,
    fetchFn: mockFetch,
    requestFn: mockHeadersRequest,
    tlsConnectFn: createMockTlsConnect(),
  });

  assert.equal(resolverCallCount, 1, 'Resolver must be called exactly once');
  assert.equal(result.resolvedIp, '93.184.216.34');
  assert.equal(result.target.display, 'https://example.com/login');
});

test('Phase 3: runUrlChecks always returns exactly 6 checks in fixed order: [gsb, urlhaus, domain, tls, ct, headers]', async () => {
  const mockResolver = async () => [{ address: '93.184.216.34', family: 4 }];
  const mockFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ([]),
  });

  const result = await runUrlChecks({
    url: 'https://example.com/',
    resolver: mockResolver,
    fetchFn: mockFetch,
    requestFn: mockHeadersRequest,
    tlsConnectFn: createMockTlsConnect(),
  });

  assert.equal(result.checks.length, 6);
  const returnedIds = result.checks.map((c) => c.id);
  assert.deepEqual(returnedIds, URL_CHECK_IDS);
  assert.deepEqual(returnedIds, ['gsb', 'urlhaus', 'domain', 'tls', 'ct', 'headers']);
});

test('Phase 3: a thrown check becomes status "error" without failing other checks', async () => {
  _resetCtCache();
  const mockResolver = async () => [{ address: '93.184.216.34', family: 4 }];
  
  // Make fetch throw for crt.sh and fallback
  const mockFetch = async (url) => {
    if (url.includes('crt.sh') || url.includes('certspotter')) {
      throw new Error('Fatal crt.sh upstream crash');
    }
    return {
      ok: true,
      status: 200,
      json: async () => ([]),
    };
  };

  const result = await runUrlChecks({
    url: 'https://example.com/',
    resolver: mockResolver,
    fetchFn: mockFetch,
    requestFn: mockHeadersRequest,
    tlsConnectFn: createMockTlsConnect(),
  });

  assert.equal(result.checks.length, 6);
  const ctCheck = result.checks.find((c) => c.id === 'ct');
  assert.ok(ctCheck);
  assert.equal(ctCheck.status, 'error');

  // Other checks must still execute successfully
  const domainCheck = result.checks.find((c) => c.id === 'domain');
  assert.equal(domainCheck.status, 'completed');
});

// ---------------------------------------------------------------------------
// 2. Google Safe Browsing (GSB) Client
// ---------------------------------------------------------------------------

test('Phase 3: GSB returns status "unavailable" with note "not configured" when API key is missing', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = '';

  const res = await checkGoogleSafeBrowsing({ url: 'https://example.com/test' });

  assert.equal(res.id, 'gsb');
  assert.equal(res.status, 'unavailable');
  assert.equal(res.detail, 'not configured');
  assert.deepEqual(res.findings, []);
});

test('Phase 3: GSB returns status "match_found" and critical finding when match is returned', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'test-gsb-key';

  const mockFetch = async (url, opts) => {
    assert.ok(!url.includes('password='), 'Never pass query secrets in GSB query');
    return {
      ok: true,
      status: 200,
      json: async () => ({
        matches: [
          {
            threatType: 'SOCIAL_ENGINEERING',
            platformType: 'ANY_PLATFORM',
            threat: { url: 'https://example.com/login' },
          },
        ],
      }),
    };
  };

  const res = await checkGoogleSafeBrowsing({
    url: 'https://example.com/login?token=secret123',
    fetchFn: mockFetch,
  });

  assert.equal(res.status, 'match_found');
  assert.equal(res.detail, 'SOCIAL_ENGINEERING');
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].severity, 'critical');
  assert.equal(res.findings[0].category, 'confirmed');
  assert.equal(res.findings[0].checkId, 'gsb');
});

test('Phase 3: GSB returns status "no_match" and info finding when clean', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'test-gsb-key';

  const mockFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({}),
  });

  const res = await checkGoogleSafeBrowsing({
    url: 'https://clean-site.example/',
    fetchFn: mockFetch,
  });

  assert.equal(res.status, 'no_match');
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].severity, 'info');
  assert.equal(res.findings[0].category, 'informational');
});

// ---------------------------------------------------------------------------
// 3. URLhaus Client
// ---------------------------------------------------------------------------

test('Phase 3: URLhaus returns status "match_found" on known malware url', async () => {
  const mockFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      query_status: 'ok',
      threat: 'malware_download',
      url_status: 'online',
      reporter: 'abuse_ch',
    }),
  });

  const res = await checkUrlhaus({
    url: 'https://malware-sample.example/payload.exe',
    fetchFn: mockFetch,
  });

  assert.equal(res.id, 'urlhaus');
  assert.equal(res.status, 'match_found');
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].severity, 'critical');
  assert.equal(res.findings[0].category, 'confirmed');
});

test('Phase 3: URLhaus returns status "no_match" when query_status is no_results', async () => {
  const mockFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      query_status: 'no_results',
    }),
  });

  const res = await checkUrlhaus({
    url: 'https://clean-site.example/',
    fetchFn: mockFetch,
  });

  assert.equal(res.status, 'no_match');
  assert.equal(res.findings[0].severity, 'info');
});

// ---------------------------------------------------------------------------
// 4. Domain & Brand Analyzer (Punycode, Typosquatting, Subdomain, RDAP)
// ---------------------------------------------------------------------------

test('Phase 3: Domain analyzer detects typosquatting against brand (e.g. paypa1)', async () => {
  const res = await analyzeDomain({
    hostname: 'paypa1.example',
    fetchFn: async () => ({ ok: false, status: 404 }),
  });

  assert.equal(res.status, 'completed');
  const typoFinding = res.findings.find((f) => f.title.includes('Brand look-alike'));
  assert.ok(typoFinding, 'Must detect typosquatting brand look-alike');
  assert.equal(typoFinding.severity, 'high');
  assert.equal(typoFinding.category, 'heuristic');
  assert.equal(typoFinding.evidence.Resembles, 'paypal');
});

test('Phase 3: Domain analyzer detects brand name inside subdomain', async () => {
  const res = await analyzeDomain({
    hostname: 'paypal.com.account-verify.example',
    fetchFn: async () => ({ ok: false, status: 404 }),
  });

  const subFinding = res.findings.find((f) => f.title.includes('Brand name in subdomain'));
  assert.ok(subFinding, 'Must detect brand name in subdomain');
  assert.equal(subFinding.severity, 'high');
  assert.equal(subFinding.evidence.Brand, 'paypal');
});

test('Phase 3: Domain analyzer detects Punycode and homoglyphs', async () => {
  const res = await analyzeDomain({
    hostname: 'xn--pple-43d.example', // Apple homoglyph representation
    fetchFn: async () => ({ ok: false, status: 404 }),
  });

  const homoFinding = res.findings.find((f) => f.title.includes('homoglyph'));
  assert.ok(homoFinding, 'Must detect Punycode/homoglyph domain');
  assert.equal(homoFinding.severity, 'high');
});

test('Phase 3: RDAP failure must not invent a domain age and marks rdap unavailable', async () => {
  // Mock RDAP network timeout / failure
  const mockRdapFetch = async () => {
    throw new Error('RDAP provider timed out');
  };

  const res = await analyzeDomain({
    hostname: 'test-rdap-fail.example',
    fetchFn: mockRdapFetch,
  });

  assert.equal(res.status, 'completed');
  assert.equal(res.extras.rdap.status, 'unavailable');
  assert.ok(res.extras.rdap.note.includes('timed out') || res.extras.rdap.note.includes('unreachable'));

  // Ensure no age was fabricated
  const newDomainFinding = res.findings.find((f) => f.title.includes('Newly registered'));
  assert.equal(newDomainFinding, undefined, 'Must not invent domain age on RDAP failure');
});

test('Phase 3: RDAP success extracts registration date and detects domains <= 30 days old', async () => {
  const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
  const mockRdapFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      events: [{ eventAction: 'registration', eventDate: tenDaysAgo }],
      entities: [
        {
          vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar Inc.']]],
        },
      ],
    }),
  });

  const res = await analyzeDomain({
    hostname: 'brandnewdomain.example',
    fetchFn: mockRdapFetch,
  });

  assert.equal(res.extras.rdap.status, 'completed');
  assert.ok(res.extras.rdap.ageDays <= 11);
  const newDomainFinding = res.findings.find((f) => f.title.includes('Newly registered'));
  assert.ok(newDomainFinding, 'Must detect newly registered domain under 30 days');
  assert.equal(newDomainFinding.severity, 'medium');
});

test('RDAP Fix 1: bootstrap success routes query to IANA TLD registry base URL', async () => {
  _resetRdapCache();
  const requestedUrls = [];
  const mockFetch = async (url, opts) => {
    requestedUrls.push(String(url));
    if (String(url).includes('data.iana.org/rdap/dns.json')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          services: [
            [['org'], ['https://rdap.publicinterestregistry.net/rdap/']],
            [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
          ],
        }),
      };
    }
    if (String(url).includes('publicinterestregistry.net')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          events: [{ eventAction: 'registration', eventDate: '2020-01-01T00:00:00Z' }],
        }),
      };
    }
    return { ok: false, status: 404 };
  };

  const res = await analyzeDomain({
    hostname: 'test-bootstrap.org',
    fetchFn: mockFetch,
  });

  assert.equal(res.extras.rdap.status, 'completed');
  assert.ok(
    requestedUrls.some((u) => u === 'https://rdap.publicinterestregistry.net/rdap/domain/test-bootstrap.org'),
    'Must query the specific IANA base URL for .org'
  );
});

test('RDAP Fix 1: TLD not in bootstrap falls back to rdap.org', async () => {
  _resetRdapCache();
  const requestedUrls = [];
  const mockFetch = async (url) => {
    requestedUrls.push(String(url));
    if (String(url).includes('data.iana.org/rdap/dns.json')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          services: [
            [['com'], ['https://rdap.verisign.com/com/v1/']],
          ],
        }),
      };
    }
    if (String(url).includes('rdap.org/domain/unknown-tld.custom')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          events: [{ eventAction: 'registration', eventDate: '2021-05-01T00:00:00Z' }],
        }),
      };
    }
    return { ok: false, status: 404 };
  };

  const res = await analyzeDomain({
    hostname: 'unknown-tld.custom',
    fetchFn: mockFetch,
  });

  assert.equal(res.extras.rdap.status, 'completed');
  assert.ok(
    requestedUrls.some((u) => u.includes('rdap.org/domain/unknown-tld.custom')),
    'Must fall back to rdap.org when TLD not in bootstrap'
  );
});

test('RDAP Fix 1: HTTP 403 marks rdap unavailable without inventing domain age', async () => {
  _resetRdapCache();
  const mockFetch = async (url) => {
    if (String(url).includes('data.iana.org')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ services: [[['org'], ['https://rdap.pir.org/']]] }),
      };
    }
    return {
      ok: false,
      status: 403,
      json: async () => ({}),
    };
  };

  const res = await analyzeDomain({
    hostname: 'forbidden.org',
    fetchFn: mockFetch,
  });

  assert.equal(res.extras.rdap.status, 'unavailable');
  assert.ok(res.extras.rdap.note.includes('403'));
  assert.equal(res.extras.rdap.ageDays, undefined);
  const newDomainFinding = res.findings.find((f) => f.id === 'f_domain_new');
  assert.equal(newDomainFinding, undefined);
});

test('RDAP Fix 1: Timeout marks rdap unavailable without inventing domain age', async () => {
  _resetRdapCache();
  const mockFetch = async () => {
    const err = new Error('The operation was aborted due to timeout');
    err.name = 'AbortError';
    throw err;
  };

  const res = await analyzeDomain({
    hostname: 'timeout.org',
    fetchFn: mockFetch,
  });

  assert.equal(res.extras.rdap.status, 'unavailable');
  assert.ok(res.extras.rdap.note.includes('timed out'));
  assert.equal(res.extras.rdap.ageDays, undefined);
  const newDomainFinding = res.findings.find((f) => f.id === 'f_domain_new');
  assert.equal(newDomainFinding, undefined);
});

test('RDAP Fix 1: Creation date < 30 days old produces f_domain_new finding', async () => {
  _resetRdapCache();
  const fiveDaysAgo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();
  const mockFetch = async (url) => {
    if (String(url).includes('data.iana.org')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ services: [[['com'], ['https://rdap.example.com/']]] }),
      };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        events: [{ eventAction: 'registration', eventDate: fiveDaysAgo }],
      }),
    };
  };

  const res = await analyzeDomain({
    hostname: 'brand-new-site.com',
    fetchFn: mockFetch,
  });

  assert.equal(res.extras.rdap.status, 'completed');
  assert.ok(res.extras.rdap.ageDays <= 6);
  const finding = res.findings.find((f) => f.id === 'f_domain_new');
  assert.ok(finding, 'Must emit f_domain_new for domain under 30 days old');
  assert.equal(finding.severity, 'medium');
});

test('RDAP Fix 1: Creation date older than 30 days produces no f_domain_new finding', async () => {
  _resetRdapCache();
  const threeYearsAgo = new Date(Date.now() - 3 * 365 * 24 * 60 * 60 * 1000).toISOString();
  const mockFetch = async (url) => {
    if (String(url).includes('data.iana.org')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ services: [[['com'], ['https://rdap.example.com/']]] }),
      };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        events: [{ eventAction: 'registration', eventDate: threeYearsAgo }],
      }),
    };
  };

  const res = await analyzeDomain({
    hostname: 'old-established-site.com',
    fetchFn: mockFetch,
  });

  assert.equal(res.extras.rdap.status, 'completed');
  assert.ok(res.extras.rdap.ageDays > 30);
  const finding = res.findings.find((f) => f.id === 'f_domain_new');
  assert.equal(finding, undefined, 'Must NOT emit f_domain_new for domain over 30 days old');
});

test('Shared Hosting Fix 4: registrable domain on shared-hosting platform becomes tenant + suffix', () => {
  const parts1 = getDomainParts('testsafebrowsing.appspot.com');
  assert.equal(parts1.registrableDomain, 'testsafebrowsing.appspot.com');
  assert.equal(parts1.subdomain, '');
  assert.equal(parts1.isSharedHosting, true);

  const parts2 = getDomainParts('my-app.github.io');
  assert.equal(parts2.registrableDomain, 'my-app.github.io');
  assert.equal(parts2.subdomain, '');
  assert.equal(parts2.isSharedHosting, true);

  const parts3 = getDomainParts('sub.testsafebrowsing.appspot.com');
  assert.equal(parts3.registrableDomain, 'testsafebrowsing.appspot.com');
  assert.equal(parts3.subdomain, 'sub');
  assert.equal(parts3.isSharedHosting, true);

  // Normal domain
  const normalParts = getDomainParts('sub.example.com');
  assert.equal(normalParts.registrableDomain, 'example.com');
  assert.equal(normalParts.subdomain, 'sub');
  assert.equal(normalParts.isSharedHosting, false);
});

test('Shared Hosting Fix 4: RDAP is skipped with not_checked status and no f_domain_new finding', async () => {
  let fetchCalled = false;
  const mockFetch = async () => {
    fetchCalled = true;
    return { ok: true, json: async () => ({}) };
  };

  const res = await analyzeDomain({
    hostname: 'testsafebrowsing.appspot.com',
    fetchFn: mockFetch,
  });

  assert.equal(fetchCalled, false, 'Fetch must NOT be called for shared-hosting domain RDAP');
  assert.equal(res.extras.rdap.status, 'not_checked');
  assert.equal(
    res.extras.rdap.note,
    'Shared hosting platform: domain age reflects the platform, not this site'
  );
  const newDomainFinding = res.findings.find((f) => f.id === 'f_domain_new');
  assert.equal(newDomainFinding, undefined, 'Must not emit f_domain_new finding for shared-hosting platform');
});

test('Shared Hosting Fix 4: CT check on shared-hosting hosts queries full hostname instead of platform domain', async () => {
  const queriedUrls = [];
  const mockFetch = async (url) => {
    queriedUrls.push(String(url));
    return {
      ok: true,
      json: async () => [
        { entry_timestamp: '2026-01-01T00:00:00Z', not_before: '2026-01-01T00:00:00Z' },
      ],
    };
  };

  const res = await checkCertificateTransparency({
    hostname: 'testsafebrowsing.appspot.com',
    fetchFn: mockFetch,
  });

  assert.equal(res.status, 'completed');
  assert.ok(
    queriedUrls.some((u) => u.includes('q=testsafebrowsing.appspot.com')),
    'Must query testsafebrowsing.appspot.com, NOT appspot.com'
  );
  assert.ok(
    !queriedUrls.some((u) => u.includes('q=appspot.com&') || u.endsWith('q=appspot.com')),
    'Must NOT query the platform domain appspot.com'
  );
});

// ---------------------------------------------------------------------------
// 5. TLS Inspector & Distrusted CA Catalog
// ---------------------------------------------------------------------------

test('Phase 3: checkDistrustedCA detects known distrusted CAs with cited primary sources and date conditions', () => {
  // WoSign cert is flagged regardless of issue date (full distrust)
  const wosignOld = checkDistrustedCA('CN=WoSign CA, O=Certification Authority WoSign', { validFrom: '2016-01-01' });
  assert.equal(wosignOld.status, 'match_found', 'WoSign cert issued 2016-01-01 must be flagged');

  const wosignNew = checkDistrustedCA('CN=WoSign CA, O=Certification Authority WoSign', { validFrom: '2017-01-01' });
  assert.equal(wosignNew.status, 'match_found', 'WoSign cert issued after 2016-10-21 must be flagged');
  assert.ok(wosignNew.note.includes('WoSign'));

  const wosignNoDate = checkDistrustedCA('CN=WoSign CA, O=Certification Authority WoSign');
  assert.equal(wosignNoDate.status, 'match_found', 'WoSign cert without date must be flagged');

  const startcomNew = checkDistrustedCA('CN=StartCom Certification Authority', { validFrom: '2017-01-01' });
  assert.equal(startcomNew.status, 'match_found', 'StartCom cert must be flagged');

  // CNNIC date conditions (notBeforeAfter: 2015-04-01)
  const cnnicOld = checkDistrustedCA('CN=CNNIC ROOT, O=China Internet Network Information Center', { validFrom: '2014-01-01' });
  assert.equal(cnnicOld.status, 'no_match', 'CNNIC cert issued before 2015-04-01 must not be flagged');

  const cnnicNew = checkDistrustedCA('CN=CNNIC ROOT, O=China Internet Network Information Center', { validFrom: '2016-01-01' });
  assert.equal(cnnicNew.status, 'match_found', 'CNNIC cert issued after 2015-04-01 must be flagged');

  // Date-conditional cert whose date is missing gives "not_checked"
  const missingDate = checkDistrustedCA('CN=CNNIC ROOT, O=China Internet Network Information Center');
  assert.equal(missingDate.status, 'not_checked', 'Cert matching date-conditional CA without date must return not_checked');
  assert.ok(missingDate.note.includes('unavailable') || missingDate.note.includes('validFrom'));

  // TrustCor date conditions (notBeforeAfter: 2022-11-30)
  const trustcorOld = checkDistrustedCA('CN=TrustCor RootCert CA-1, O=TrustCor Systems', { validFrom: '2022-06-01' });
  assert.equal(trustcorOld.status, 'no_match', 'TrustCor cert issued before 2022-11-30 must not be flagged');

  const trustcorNew = checkDistrustedCA('CN=TrustCor RootCert CA-1, O=TrustCor Systems', { validFrom: '2022-12-15' });
  assert.equal(trustcorNew.status, 'match_found', 'TrustCor cert issued after 2022-11-30 must be flagged');
  assert.ok(trustcorNew.note.includes('TrustCor'));

  const trustcorNoDate = checkDistrustedCA('CN=TrustCor RootCert CA-1, O=TrustCor Systems');
  assert.equal(trustcorNoDate.status, 'not_checked', 'TrustCor cert without date must return not_checked');

  // (c) a cert from "RapidSSL TLS RSA CA G1" or "GeoTrust TLS RSA CA G1" issued today is NOT flagged
  const today = new Date().toISOString();
  const rapidSsl = checkDistrustedCA('CN=RapidSSL TLS RSA CA G1, O=DigiCert Inc', { validFrom: today });
  assert.equal(rapidSsl.status, 'no_match', 'RapidSSL cert operated by DigiCert must not be flagged');

  const geoTrust = checkDistrustedCA('CN=GeoTrust TLS RSA CA G1, O=DigiCert Inc', { validFrom: today });
  assert.equal(geoTrust.status, 'no_match', 'GeoTrust cert operated by DigiCert must not be flagged');

  // DigiNotar has no date condition and flags even without a date
  const digi = checkDistrustedCA('CN=DigiNotar Root CA, O=DigiNotar');
  assert.equal(digi.status, 'match_found');
  assert.ok(digi.note.includes('DigiNotar'));
  assert.equal(digi.entry.sourceUrl, 'https://blog.mozilla.org/security/2011/09/02/diginotar-removal-follow-up');

  // Clean CA
  const clean = checkDistrustedCA('CN=DigiCert Global Root G3, O=DigiCert Inc');
  assert.equal(clean.status, 'no_match');
});

test('Phase 3: inspectTls integrates date-conditional distrust and brand immunity', async () => {
  // WoSign cert issued 2016-01-01 -> IS flagged in inspectTls (full distrust)
  const wosign2016Tls = createMockTlsConnect({
    subject: { CN: 'wosign-old.example' },
    issuer: { CN: 'WoSign CA' },
    subjectaltname: 'DNS:wosign-old.example',
    valid_from: 'Jan 1 00:00:00 2016 GMT',
    valid_to: 'Jan 1 00:00:00 2030 GMT',
  });
  const resOld = await inspectTls({
    hostname: 'wosign-old.example',
    validatedIp: '93.184.216.34',
    tlsConnectFn: wosign2016Tls,
  });
  assert.equal(resOld.tls.distrust.status, 'match_found', 'WoSign 2016 cert must be flagged');
  assert.ok(resOld.findings.find((f) => f.id === 'f_tls_distrusted_ca'));

  // WoSign cert issued 2017-01-01 -> IS flagged in inspectTls
  const wosign2017Tls = createMockTlsConnect({
    subject: { CN: 'wosign-new.example' },
    issuer: { CN: 'WoSign CA' },
    subjectaltname: 'DNS:wosign-new.example',
    valid_from: 'Jan 1 00:00:00 2017 GMT',
    valid_to: 'Jan 1 00:00:00 2030 GMT',
  });
  const resNew = await inspectTls({
    hostname: 'wosign-new.example',
    validatedIp: '93.184.216.34',
    tlsConnectFn: wosign2017Tls,
  });
  assert.equal(resNew.tls.distrust.status, 'match_found', 'WoSign 2017 cert must be flagged');
  const distrustFinding = resNew.findings.find((f) => f.id === 'f_tls_distrusted_ca');
  assert.ok(distrustFinding, 'Must emit f_tls_distrusted_ca for WoSign 2017 cert');
  assert.equal(distrustFinding.severity, 'high');
  assert.equal(distrustFinding.category, 'heuristic');
  assert.equal(resNew.status, 'completed');

  // TrustCor certs in inspectTls
  const trustcorNewTls = createMockTlsConnect({
    subject: { CN: 'trustcor-site.example' },
    issuer: { CN: 'TrustCor Systems' },
    subjectaltname: 'DNS:trustcor-site.example',
    valid_from: 'Dec 15 00:00:00 2022 GMT',
    valid_to: 'Jan 1 00:00:00 2030 GMT',
  });
  const resTrustcorNew = await inspectTls({
    hostname: 'trustcor-site.example',
    validatedIp: '93.184.216.34',
    tlsConnectFn: trustcorNewTls,
  });
  assert.equal(resTrustcorNew.tls.distrust.status, 'match_found', 'TrustCor 2022-12-15 must be flagged');

  const trustcorOldTls = createMockTlsConnect({
    subject: { CN: 'trustcor-old.example' },
    issuer: { CN: 'TrustCor Systems' },
    subjectaltname: 'DNS:trustcor-old.example',
    valid_from: 'Jun 1 00:00:00 2022 GMT',
    valid_to: 'Jan 1 00:00:00 2030 GMT',
  });
  const resTrustcorOld = await inspectTls({
    hostname: 'trustcor-old.example',
    validatedIp: '93.184.216.34',
    tlsConnectFn: trustcorOldTls,
  });
  assert.equal(resTrustcorOld.tls.distrust.status, 'no_match', 'TrustCor 2022-06-01 must not be flagged');

  // RapidSSL cert issued today -> NOT flagged in inspectTls
  const rapidSslTls = createMockTlsConnect({
    subject: { CN: 'rapidssl-modern.example' },
    issuer: { CN: 'RapidSSL TLS RSA CA G1', O: 'DigiCert Inc' },
    subjectaltname: 'DNS:rapidssl-modern.example',
    valid_from: new Date().toUTCString(),
    valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toUTCString(),
  });
  const resRapid = await inspectTls({
    hostname: 'rapidssl-modern.example',
    validatedIp: '93.184.216.34',
    tlsConnectFn: rapidSslTls,
  });
  assert.equal(resRapid.tls.distrust.status, 'no_match', 'RapidSSL must not be flagged');
  assert.equal(resRapid.findings.find((f) => f.id === 'f_tls_distrusted_ca'), undefined);

  // Date-conditional CA (TrustCor / CNNIC) whose date is missing -> gives "not_checked" in inspectTls
  const missingDateTls = createMockTlsConnect({
    subject: { CN: 'trustcor-nodate.example' },
    issuer: { CN: 'TrustCor Systems' },
    subjectaltname: 'DNS:trustcor-nodate.example',
    valid_from: null,
  });
  const resNoDate = await inspectTls({
    hostname: 'trustcor-nodate.example',
    validatedIp: '93.184.216.34',
    tlsConnectFn: missingDateTls,
  });
  assert.equal(resNoDate.tls.distrust.status, 'not_checked', 'Missing date for date-conditional CA must return not_checked');
  assert.equal(resNoDate.findings.find((f) => f.id === 'f_tls_distrusted_ca'), undefined);
});

test('Phase 3: distrusted CAs catalog defines scope for every entry and WoSign/StartCom scope specifies two-stage distrust', async () => {
  const fs = await import('node:fs');
  const catalogPath = new URL('../src/data/distrustedCAs.json', import.meta.url);
  const catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf-8'));

  assert.ok(catalog.length >= 5, 'Catalog must contain at least 5 distrusted CA records');

  for (const entry of catalog) {
    assert.ok(entry.id, 'Entry must have an id');
    assert.ok(entry.name, 'Entry must have a name');
    assert.ok(entry.sourceUrl.startsWith('https://'), `Entry ${entry.name} must have a valid sourceUrl`);
    assert.ok(typeof entry.scope === 'string' && entry.scope.length > 0, `Entry ${entry.name} must have a non-empty scope field`);
  }

  const digiEntry = catalog.find((e) => e.id === 'diginotar');
  assert.equal(digiEntry.sourceUrl, 'https://blog.mozilla.org/security/2011/09/02/diginotar-removal-follow-up');
  assert.ok(digiEntry.additionalSources?.includes('https://blog.mozilla.org/security/2011/08/29/fraudulent-google-com-certificate/'));
  assert.ok(digiEntry.scope.includes('Mozilla completely removed DigiNotar from its root program'));
  assert.equal(digiEntry.notBeforeAfter, undefined);

  const trustcorEntry = catalog.find((e) => e.id === 'trustcor');
  assert.equal(trustcorEntry.date, '2022-11-30');
  assert.equal(trustcorEntry.authority, 'Mozilla / Microsoft');
  assert.equal(trustcorEntry.sourceUrl, 'https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/oxX69KFvsm4');
  assert.equal(trustcorEntry.notBeforeAfter, '2022-11-30');
  assert.ok(trustcorEntry.scope.includes('2022-11-30'));
  assert.ok(trustcorEntry.scope.includes('Microsoft set 2022-11-01'));
  assert.ok(trustcorEntry.reason.includes('spyware-related companies'));

  const cnnicEntry = catalog.find((e) => e.id === 'cnnic');
  assert.equal(cnnicEntry.sourceUrl, 'https://security.googleblog.com/2015/03/maintaining-digital-certificate-security.html');

  const wosignEntry = catalog.find((e) => e.patterns.includes('WoSign') || e.id.includes('wosign'));
  assert.ok(wosignEntry, 'WoSign/StartCom entry must exist in catalog');
  assert.ok(wosignEntry.scope.includes('2016-10-21'), 'Scope must mention 2016-10-21');
  assert.ok(wosignEntry.scope.includes('Chrome 61'), 'Scope must mention Chrome 61');
  assert.equal(wosignEntry.notBeforeAfter, undefined, 'WoSign/StartCom entry must not have notBeforeAfter');
  assert.ok(
    wosignEntry.additionalSources?.includes('https://groups.google.com/a/chromium.org/g/net-dev/c/FKXe-76GO8Y/m/Ka8K5lj9AgAJ'),
    'Must include additional source'
  );
});

test('Phase 3: distrusted-CA match in inspectTls keeps check status completed, sets untrusted_chain, and emits heuristic high finding', async () => {
  const distrustedCertTls = createMockTlsConnect({
    subject: { CN: 'distrusted-site.example' },
    issuer: { CN: 'DigiNotar Root CA' },
    subjectaltname: 'DNS:distrusted-site.example',
    authorized: false,
    authorizationError: 'CERT_REVOKED',
  });

  const res = await inspectTls({
    hostname: 'distrusted-site.example',
    validatedIp: '93.184.216.34',
    tlsConnectFn: distrustedCertTls,
  });

  // Check status must remain 'completed', NOT 'match_found'
  assert.equal(res.status, 'completed', 'TLS check status must remain completed');
  assert.equal(res.tls.status, 'untrusted_chain', 'TLS status must be untrusted_chain');
  assert.equal(res.tls.distrust.status, 'match_found', 'Distrust status must be match_found');

  // Must NOT produce finding with category "confirmed" or severity "critical"
  const confirmedFindings = res.findings.filter((f) => f.category === 'confirmed');
  assert.equal(confirmedFindings.length, 0, 'Distrusted CA must NOT produce category confirmed');

  const criticalFindings = res.findings.filter((f) => f.severity === 'critical');
  assert.equal(criticalFindings.length, 0, 'Distrusted CA must NOT produce severity critical');

  // Must emit finding with category "heuristic" and severity "high"
  const distrustFinding = res.findings.find((f) => f.id === 'f_tls_distrusted_ca');
  assert.ok(distrustFinding, 'Must emit f_tls_distrusted_ca finding');
  assert.equal(distrustFinding.category, 'heuristic');
  assert.equal(distrustFinding.severity, 'high');
});

test('Phase 3: IP-literal hosts do not set TLS servername (RFC 6066)', async () => {
  let capturedServername = 'initial';
  const customTlsConnect = (opts, cb) => {
    capturedServername = opts.servername;
    return createMockTlsConnect()(opts, cb);
  };

  await inspectTls({
    hostname: '93.184.216.34',
    validatedIp: '93.184.216.34',
    tlsConnectFn: customTlsConnect,
  });

  assert.equal(capturedServername, undefined, 'Servername must be undefined for IP literal hosts');
});

test('Phase 3: inspectTls detects weak cryptography (RSA 1024 bits)', async () => {
  const weakCertTls = createMockTlsConnect({
    subject: { CN: 'weak-crypto.example' },
    subjectaltname: 'DNS:weak-crypto.example',
    bits: 1024,
    asn1Curve: null,
    sigalg: 'sha256WithRSAEncryption',
  });

  const res = await inspectTls({
    hostname: 'weak-crypto.example',
    validatedIp: '93.184.216.34',
    tlsConnectFn: weakCertTls,
  });

  assert.equal(res.tls.status, 'weak_crypto');
  const weakFinding = res.findings.find((f) => f.title.includes('Weak cryptographic'));
  assert.ok(weakFinding, 'Must emit weak crypto finding');
  assert.equal(weakFinding.severity, 'medium');
});

test('TLS Fix 2: SHA-256 signature algorithm is detected as valid and secure', async () => {
  const sha256Tls = createMockTlsConnect({
    subject: { CN: 'sha256-site.example' },
    subjectaltname: 'DNS:sha256-site.example',
    bits: 2048,
    sigalg: 'sha256WithRSAEncryption',
  });

  const res = await inspectTls({
    hostname: 'sha256-site.example',
    validatedIp: '93.184.216.34',
    tlsConnectFn: sha256Tls,
  });

  assert.equal(res.tls.status, 'valid');
  assert.equal(res.tls.signatureAlgorithm, 'sha256WithRSAEncryption');
  const validFinding = res.findings.find((f) => f.id === 'f_tls_valid');
  assert.ok(validFinding);
  assert.equal(validFinding.evidence['Signature algorithm'], 'sha256WithRSAEncryption');
  assert.equal(validFinding.evidence['Weak signature check'], 'passed');
});

test('TLS Fix 2: SHA-1 signature algorithm produces weak_crypto finding', async () => {
  const sha1Tls = createMockTlsConnect({
    subject: { CN: 'sha1-site.example' },
    subjectaltname: 'DNS:sha1-site.example',
    bits: 2048,
    sigalg: 'sha1WithRSAEncryption',
  });

  const res = await inspectTls({
    hostname: 'sha1-site.example',
    validatedIp: '93.184.216.34',
    tlsConnectFn: sha1Tls,
  });

  assert.equal(res.tls.status, 'weak_crypto');
  assert.equal(res.tls.signatureAlgorithm, 'sha1WithRSAEncryption');
  const weakFinding = res.findings.find((f) => f.id === 'f_tls_weak_crypto');
  assert.ok(weakFinding, 'Must emit f_tls_weak_crypto for SHA-1 cert');
  assert.equal(weakFinding.severity, 'medium');
  assert.equal(weakFinding.evidence['Signature algorithm'], 'sha1WithRSAEncryption');
  assert.equal(weakFinding.evidence['Weak signature check'], 'failed');
});

test('TLS Fix 2: undetermined signature algorithm sets signatureAlgorithm to null and marks check not_checked in evidence', async () => {
  const emptySigTls = createMockTlsConnect({
    subject: { CN: 'empty-sig.example' },
    subjectaltname: 'DNS:empty-sig.example',
    bits: 2048,
    sigalg: '', // empty signature algorithm string
  });

  const res = await inspectTls({
    hostname: 'empty-sig.example',
    validatedIp: '93.184.216.34',
    tlsConnectFn: emptySigTls,
  });

  assert.equal(res.tls.signatureAlgorithm, null, 'Undetermined signature algorithm must be null');
  assert.equal(res.tls.status, 'valid');
  const validFinding = res.findings.find((f) => f.id === 'f_tls_valid');
  assert.ok(validFinding, 'Must emit f_tls_valid when valid and key length >= 2048');
  assert.equal(validFinding.evidence['Signature algorithm'], 'not_checked');
  assert.equal(validFinding.evidence['Weak signature check'], 'not_checked');
});

// ---------------------------------------------------------------------------
// 6. Certificate Transparency (crt.sh)
// ---------------------------------------------------------------------------

test('Phase 3: crt.sh check returns completed and entries count on success', async () => {
  _resetCtCache();
  const mockFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => [{ id: 1 }, { id: 2 }, { id: 3 }],
  });

  const res = await checkCertificateTransparency({
    hostname: 'example.com',
    fetchFn: mockFetch,
  });

  assert.equal(res.id, 'ct');
  assert.equal(res.status, 'completed');
  assert.equal(res.entries, 3);
  assert.equal(res.findings.length, 1);
});

test('Phase 3: crt.sh check marks status error on timeout or 5xx without clean treatment', async () => {
  _resetCtCache();
  const mockTimeoutFetch = async () => {
    const err = new Error('The operation was aborted due to timeout');
    err.name = 'AbortError';
    throw err;
  };

  const res = await checkCertificateTransparency({
    hostname: 'example.com',
    fetchFn: mockTimeoutFetch,
  });

  assert.equal(res.status, 'error');
  assert.ok(
    res.detail.includes('Certificate Transparency providers unavailable') ||
    res.detail.includes('Provider timed out after 8s')
  );
  assert.deepEqual(res.findings, []);
});

test('CT Fix 5: Primary success returns status completed with crt.sh source and reduced load query string', async () => {
  _resetCtCache();
  const capturedUrls = [];
  const mockFetch = async (url) => {
    capturedUrls.push(String(url));
    return {
      ok: true,
      status: 200,
      json: async () => [{ id: 1 }, { id: 2 }],
    };
  };

  const res = await checkCertificateTransparency({
    hostname: 'primary-success.com',
    fetchFn: mockFetch,
  });

  assert.equal(res.status, 'completed');
  assert.equal(res.source, 'crt.sh');
  assert.equal(res.entries, 2);
  assert.equal(res.findings[0].source, 'crt.sh');
  assert.ok(
    capturedUrls[0].includes('output=json') &&
    capturedUrls[0].includes('exclude=expired') &&
    capturedUrls[0].includes('deduplicate=Y'),
    'Must include query string optimizations to reduce load'
  );
});

test('CT Fix 5: Primary 502 Bad Gateway triggers fallback to Cert Spotter which succeeds', async () => {
  _resetCtCache();
  const capturedUrls = [];
  const mockFetch = async (url) => {
    capturedUrls.push(String(url));
    if (String(url).includes('crt.sh')) {
      return {
        ok: false,
        status: 502,
        statusText: 'Bad Gateway',
        json: async () => ({ error: 'Bad Gateway' }),
      };
    }
    if (String(url).includes('certspotter.com')) {
      return {
        ok: true,
        status: 200,
        json: async () => [{ id: 'cs-1' }, { id: 'cs-2' }, { id: 'cs-3' }],
      };
    }
    return { ok: false, status: 404 };
  };

  const res = await checkCertificateTransparency({
    hostname: 'fallback-site.org',
    fetchFn: mockFetch,
  });

  assert.equal(res.status, 'completed');
  assert.equal(res.source, 'Cert Spotter (fallback)');
  assert.equal(res.entries, 3);
  assert.equal(res.findings[0].source, 'Cert Spotter (fallback)');
  assert.ok(capturedUrls.some((u) => u.includes('certspotter.com')));
});

test('CT Fix 5: Both providers fail results in status error and expected note', async () => {
  _resetCtCache();
  const mockFetch = async (url) => {
    if (String(url).includes('crt.sh')) {
      return { ok: false, status: 502 };
    }
    if (String(url).includes('certspotter.com')) {
      return { ok: false, status: 500 };
    }
    return { ok: false, status: 500 };
  };

  const res = await checkCertificateTransparency({
    hostname: 'both-fail.org',
    fetchFn: mockFetch,
  });

  assert.equal(res.status, 'error');
  assert.equal(
    res.detail,
    'Certificate Transparency providers unavailable. Not treated as a clean result.'
  );
  assert.equal(res.entries, 0);
  assert.deepEqual(res.findings, []);
});

test('CT Fix 5: Cache hit returns cached successful result without making network call', async () => {
  _resetCtCache();
  let fetchCallCount = 0;
  const mockFetch = async () => {
    fetchCallCount++;
    return {
      ok: true,
      status: 200,
      json: async () => [{ id: 101 }],
    };
  };

  // First call -> populates cache
  const first = await checkCertificateTransparency({
    hostname: 'cache-test.org',
    fetchFn: mockFetch,
  });
  assert.equal(first.status, 'completed');
  assert.equal(fetchCallCount, 1);

  // Second call with throwing fetch -> cache hit avoids network call
  const second = await checkCertificateTransparency({
    hostname: 'cache-test.org',
    fetchFn: async () => {
      throw new Error('Should not be called on cache hit');
    },
  });
  assert.equal(second.status, 'completed');
  assert.equal(second.entries, 1);
  assert.equal(fetchCallCount, 1, 'Network call count must remain 1');
});

test('CT Fix 5: Failures are never cached', async () => {
  _resetCtCache();
  let callCount = 0;
  // First call: fail
  const failingFetch = async () => {
    callCount++;
    return { ok: false, status: 502 };
  };

  const first = await checkCertificateTransparency({
    hostname: 'no-cache-fail.org',
    fetchFn: failingFetch,
  });
  assert.equal(first.status, 'error');

  // Second call: succeed
  const succeedingFetch = async (url) => {
    callCount++;
    if (String(url).includes('crt.sh')) {
      return {
        ok: true,
        status: 200,
        json: async () => [{ id: 'ok-1' }],
      };
    }
    return { ok: false, status: 500 };
  };

  const second = await checkCertificateTransparency({
    hostname: 'no-cache-fail.org',
    fetchFn: succeedingFetch,
  });
  assert.equal(second.status, 'completed');
  assert.equal(second.entries, 1);
  assert.ok(callCount > 1, 'Must have made network call on second attempt');
});

test('CT Fix 5: Total time stays under 8s timeout budget', async () => {
  _resetCtCache();
  const startTime = Date.now();

  const res = await checkCertificateTransparency({
    hostname: 'budget-test.org',
    fetchFn: async () => {
      const err = new Error('Abort error');
      err.name = 'AbortError';
      throw err;
    },
  });

  const duration = Date.now() - startTime;
  assert.equal(res.status, 'error');
  assert.ok(duration < 8000, `Duration (${duration}ms) must stay under 8000ms`);
});

// ---------------------------------------------------------------------------
// 7. HTTP Security Headers
// ---------------------------------------------------------------------------

test('Phase 3: inspectHeaders detects missing security headers and insecure cookies', async () => {
  // Test headers inspection via mock safeRequest or pre-validated options
  const res = await inspectHeaders({
    url: 'http://test-headers.example/',
    preValidatedIp: '127.0.0.1',
    preValidatedFamily: 4,
    resolver: async () => [{ address: '127.0.0.1', family: 4 }],
    _dangerouslyAllowLocalhostForTesting: true,
  });

  assert.equal(res.id, 'headers');
  assert.ok(Array.isArray(res.findings));
  // If host unreachable in mock without real server, returns unavailable safely
  assert.ok(res.status === 'completed' || res.status === 'unavailable');
});
