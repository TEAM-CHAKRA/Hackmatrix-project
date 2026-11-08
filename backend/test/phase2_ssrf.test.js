import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  validateTargetUrl,
  resolveAndValidate,
  isForbiddenIp,
  SsrfError,
} from '../src/services/ssrfValidator.js';
import {
  safeRequest,
  redactSensitiveQueryParams,
} from '../src/services/safeHttpClient.js';
import { createInvestigation } from '../src/controllers/investigationController.js';
import { repository } from '../src/store/repository.js';
import { ERROR_CODES } from '../src/config/constants.js';

function createMockRes() {
  return {
    statusCode: 200,
    headers: {},
    body: null,
    setHeader(name, val) {
      this.headers[name.toLowerCase()] = val;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.body = data;
      return this;
    },
  };
}

// ---------------------------------------------------------------------------
// 1. Blocked IPs and Encodings
// ---------------------------------------------------------------------------

test('SSRF: isForbiddenIp correctly blocks private, loopback, link-local, and special ranges', () => {
  // IPv4 blocked
  assert.equal(isForbiddenIp('127.0.0.1'), true, '127.0.0.1 must be blocked');
  assert.equal(isForbiddenIp('169.254.169.254'), true, '169.254.169.254 must be blocked');
  assert.equal(isForbiddenIp('10.0.0.5'), true, '10.0.0.5 must be blocked');
  assert.equal(isForbiddenIp('172.16.0.1'), true, '172.16.0.1 must be blocked');
  assert.equal(isForbiddenIp('192.168.1.1'), true, '192.168.1.1 must be blocked');
  assert.equal(isForbiddenIp('198.18.0.1'), true, '198.18.0.0/15 must be blocked');
  assert.equal(isForbiddenIp('0.0.0.0'), true, '0.0.0.0 must be blocked');
  assert.equal(isForbiddenIp('255.255.255.255'), true, '255.255.255.255 must be blocked');

  // IPv6 blocked
  assert.equal(isForbiddenIp('::1'), true, '::1 must be blocked');
  assert.equal(isForbiddenIp('::'), true, ':: must be blocked');
  assert.equal(isForbiddenIp('::ffff:127.0.0.1'), true, '::ffff:127.0.0.1 must be blocked');
  assert.equal(isForbiddenIp('::ffff:7f00:1'), true, '::ffff:7f00:1 must be blocked');
  assert.equal(isForbiddenIp('fe80::1'), true, 'fe80::1 link-local must be blocked');
  assert.equal(isForbiddenIp('fc00::1'), true, 'fc00::1 ULA must be blocked');
  assert.equal(isForbiddenIp('64:ff9b::192.0.2.1'), true, '64:ff9b:: translation range must be blocked');
  assert.equal(isForbiddenIp('2001:db8::1'), true, '2001:db8::/32 documentation must be blocked');
  assert.equal(isForbiddenIp('2001::1'), true, '2001::/32 Teredo must be blocked');
  assert.equal(isForbiddenIp('2002::1'), true, '2002::/16 6to4 must be blocked');

  // Public allowed
  assert.equal(isForbiddenIp('93.184.216.34'), false, '93.184.216.34 must be allowed');
  assert.equal(isForbiddenIp('2606:2800:220:1:248:1893:25c8:1946'), false, 'Public IPv6 must be allowed');
});

test('SSRF: validateTargetUrl blocks unusual IP encodings, credentials, schemes, and ports', () => {
  // Numeric, hex, and octal IP encodings
  assert.throws(
    () => validateTargetUrl('http://2130706433/'),
    (err) => err instanceof SsrfError && err.code === ERROR_CODES.SSRF_BLOCKED
  );

  assert.throws(
    () => validateTargetUrl('http://134744072/'),
    (err) => err instanceof SsrfError && err.code === ERROR_CODES.SSRF_BLOCKED,
    'http://134744072/ (raw numeric normalizing to 8.8.8.8) must be blocked'
  );

  assert.throws(
    () => validateTargetUrl('http://0x7f.0.0.1/'),
    (err) => err instanceof SsrfError && err.code === ERROR_CODES.SSRF_BLOCKED
  );

  assert.throws(
    () => validateTargetUrl('http://0177.0.0.1/'),
    (err) => err instanceof SsrfError && err.code === ERROR_CODES.SSRF_BLOCKED
  );

  // Embedded credentials user:pass@
  assert.throws(
    () => validateTargetUrl('http://user:pass@example.com'),
    (err) => err instanceof SsrfError && err.code === ERROR_CODES.VALIDATION_ERROR
  );

  // Restricted port 8080
  assert.throws(
    () => validateTargetUrl('http://example.com:8080/'),
    (err) => err instanceof SsrfError && err.code === ERROR_CODES.SSRF_BLOCKED
  );

  // Non-HTTP(S) schemes
  for (const schemeUrl of ['file:///etc/passwd', 'ftp://example.com/', 'javascript:alert(1)', 'data:text/html,hello']) {
    assert.throws(
      () => validateTargetUrl(schemeUrl),
      (err) => err instanceof SsrfError && err.code === ERROR_CODES.VALIDATION_ERROR,
      `Scheme URL ${schemeUrl} should be rejected`
    );
  }

  // Length > 2048
  const longUrl = 'https://example.com/' + 'a'.repeat(2050);
  assert.throws(
    () => validateTargetUrl(longUrl),
    (err) => err instanceof SsrfError && err.code === ERROR_CODES.VALIDATION_ERROR
  );
});

// ---------------------------------------------------------------------------
// 2. DNS Resolution and Validation
// ---------------------------------------------------------------------------

test('SSRF: resolveAndValidate blocks localhost resolving to 127.0.0.1', async () => {
  const mockResolver = async (host) => [{ address: '127.0.0.1', family: 4 }];

  await assert.rejects(
    async () => resolveAndValidate('localhost', { resolver: mockResolver }),
    (err) => err instanceof SsrfError && err.code === ERROR_CODES.SSRF_BLOCKED
  );
});

test('SSRF: a hostname resolving to one public and one private IP is blocked', async () => {
  const mixedResolver = async (host) => [
    { address: '93.184.216.34', family: 4 },
    { address: '10.0.0.1', family: 4 },
  ];

  await assert.rejects(
    async () => resolveAndValidate('dual-homed.example', { resolver: mixedResolver }),
    (err) => err instanceof SsrfError && err.code === ERROR_CODES.SSRF_BLOCKED
  );
});

test('SSRF: allowed public IP 93.184.216.34 via injected resolver', async () => {
  const publicResolver = async (host) => [{ address: '93.184.216.34', family: 4 }];
  const res = await resolveAndValidate('public.example', { resolver: publicResolver });

  assert.equal(res.ip, '93.184.216.34');
  assert.equal(res.family, 4);
  assert.deepEqual(res.addresses, ['93.184.216.34']);
});

// ---------------------------------------------------------------------------
// 3. DNS Pinning Guarantees
// ---------------------------------------------------------------------------

test('SSRF: DNS pinning - resolver is called exactly once per request and subsequent IP changes are ignored', async () => {
  let resolverCallCount = 0;
  const mutatingResolver = async (host) => {
    resolverCallCount++;
    if (resolverCallCount === 1) {
      return [{ address: '127.0.0.1', family: 4 }];
    }
    // If called again, would return a different IP (DNS rebinding simulation)
    return [{ address: '192.168.1.1', family: 4 }];
  };

  // We test on a local server using test-only localhost bypass
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('pinned-response');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const res = await safeRequest('http://rebinding-test.example/', {
      resolver: mutatingResolver,
      _dangerouslyAllowLocalhostForTesting: true,
      _portOverrideForTesting: port,
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.bodySnippet, 'pinned-response');
    assert.equal(resolverCallCount, 1, 'Resolver must be called exactly once per hop');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('SSRF: safeRequest with preValidatedIp does not call resolver on first hop', async () => {
  let resolverCalled = false;
  const dummyResolver = async () => {
    resolverCalled = true;
    return [{ address: '127.0.0.1', family: 4 }];
  };

  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('pre-validated-response');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const res = await safeRequest('http://preval.example/', {
      preValidatedIp: '127.0.0.1',
      preValidatedFamily: 4,
      resolver: dummyResolver,
      _dangerouslyAllowLocalhostForTesting: true,
      _portOverrideForTesting: port,
    });

    assert.equal(res.statusCode, 200);
    assert.equal(res.bodySnippet, 'pre-validated-response');
    assert.equal(resolverCalled, false, 'Resolver should not be called when preValidatedIp is provided');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('SSRF: redirect to a private IP is blocked during redirect hop', async () => {
  const redirectServer = http.createServer((req, res) => {
    // Redirect to private IP
    res.writeHead(302, { Location: 'http://10.0.0.1/internal' });
    res.end();
  });

  await new Promise((resolve) => redirectServer.listen(0, '127.0.0.1', resolve));
  const port = redirectServer.address().port;

  try {
    await assert.rejects(
      async () =>
        safeRequest('http://redirect-hop.example/', {
          resolver: async () => [{ address: '127.0.0.1', family: 4 }],
          _dangerouslyAllowLocalhostForTesting: true,
          _portOverrideForTesting: port,
        }),
      (err) => err instanceof SsrfError && err.code === ERROR_CODES.SSRF_BLOCKED
    );
  } finally {
    await new Promise((resolve) => redirectServer.close(resolve));
  }
});

test('SSRF: redirect loop is detected and terminated', async () => {
  const loopServer = http.createServer((req, res) => {
    if (req.url === '/a') {
      res.writeHead(302, { Location: '/b' });
      res.end();
    } else {
      res.writeHead(302, { Location: '/a' });
      res.end();
    }
  });

  await new Promise((resolve) => loopServer.listen(0, '127.0.0.1', resolve));
  const port = loopServer.address().port;

  try {
    await assert.rejects(
      async () =>
        safeRequest('http://loop.example/a', {
          resolver: async () => [{ address: '127.0.0.1', family: 4 }],
          _dangerouslyAllowLocalhostForTesting: true,
          _portOverrideForTesting: port,
        }),
      (err) => err instanceof SsrfError && err.message.includes('Redirect loop detected')
    );
  } finally {
    await new Promise((resolve) => loopServer.close(resolve));
  }
});

test('SSRF: maximum redirect limit of 5 hops is enforced', async () => {
  let counter = 0;
  const chainServer = http.createServer((req, res) => {
    counter++;
    res.writeHead(302, { Location: `/hop-${counter}` });
    res.end();
  });

  await new Promise((resolve) => chainServer.listen(0, '127.0.0.1', resolve));
  const port = chainServer.address().port;

  try {
    await assert.rejects(
      async () =>
        safeRequest('http://chain.example/hop-0', {
          maxRedirects: 5,
          resolver: async () => [{ address: '127.0.0.1', family: 4 }],
          _dangerouslyAllowLocalhostForTesting: true,
          _portOverrideForTesting: port,
        }),
      (err) => err instanceof SsrfError && err.message.includes('Maximum redirect limit')
    );
  } finally {
    await new Promise((resolve) => chainServer.close(resolve));
  }
});

test('SSRF: query parameter redaction in redirectChain and URLs', () => {
  const raw =
    'https://example.com/login?token=secret123&session=sess456&auth=tok789&key=keyabc&password=p1&code=authcode&sig=sigval&signature=sig2&secret=s1&apikey=api9&normal=safeValue';

  const redacted = redactSensitiveQueryParams(raw);

  assert.ok(!redacted.includes('secret123'), 'token must be redacted');
  assert.ok(!redacted.includes('sess456'), 'session must be redacted');
  assert.ok(!redacted.includes('tok789'), 'auth must be redacted');
  assert.ok(!redacted.includes('keyabc'), 'key must be redacted');
  assert.ok(!redacted.includes('authcode'), 'code must be redacted');
  assert.ok(!redacted.includes('sigval'), 'sig must be redacted');
  assert.ok(!redacted.includes('sig2'), 'signature must be redacted');
  assert.ok(!redacted.includes('api9'), 'apikey must be redacted');
  assert.ok(redacted.includes('normal=safeValue'), 'non-sensitive parameter must be preserved');
  assert.ok(redacted.includes('token=%5Bredacted%5D') || redacted.includes('token=[redacted]'));
});

// ---------------------------------------------------------------------------
// 5. Response Size Limit, Timeout & Real Pinned Connection
// ---------------------------------------------------------------------------

test('SSRF: response size exceeding maxBytes is truncated and connection destroyed', async () => {
  const streamServer = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
    // Write 50KB in chunks
    const chunk = Buffer.alloc(1024, 'A');
    for (let i = 0; i < 50; i++) {
      res.write(chunk);
    }
    res.end();
  });

  await new Promise((resolve) => streamServer.listen(0, '127.0.0.1', resolve));
  const port = streamServer.address().port;

  try {
    const res = await safeRequest('http://large-stream.example/', {
      maxBytes: 10 * 1024, // 10KB limit
      resolver: async () => [{ address: '127.0.0.1', family: 4 }],
      _dangerouslyAllowLocalhostForTesting: true,
      _portOverrideForTesting: port,
    });

    assert.equal(res.truncated, true, 'Response must be marked truncated when exceeding maxBytes');
    assert.ok(res.bodySnippet.length <= 4096, 'Snippet must not exceed maximum snippet size');
  } finally {
    await new Promise((resolve) => streamServer.close(resolve));
  }
});

test('SSRF: request exceeding timeoutMs aborts with timeout error', async () => {
  const slowServer = http.createServer((req, res) => {
    // Hangs response beyond timeout
    setTimeout(() => {
      res.writeHead(200);
      res.end('too late');
    }, 500);
  });

  await new Promise((resolve) => slowServer.listen(0, '127.0.0.1', resolve));
  const port = slowServer.address().port;

  try {
    await assert.rejects(
      async () =>
        safeRequest('http://slow.example/', {
          timeoutMs: 100, // 100ms timeout
          resolver: async () => [{ address: '127.0.0.1', family: 4 }],
          _dangerouslyAllowLocalhostForTesting: true,
          _portOverrideForTesting: port,
        }),
      (err) => err.code === 'ETIMEDOUT' || err.message.includes('timed out')
    );
  } finally {
    await new Promise((resolve) => slowServer.close(resolve));
  }
});

test('SSRF: real request through pinned agent to local server verifies connection and headers', async () => {
  let serverReceivedHostHeader = '';
  let serverReceivedUserAgent = '';

  const server = http.createServer((req, res) => {
    serverReceivedHostHeader = req.headers.host;
    serverReceivedUserAgent = req.headers['user-agent'];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'real-connection-verified' }));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const res = await safeRequest('http://verified-connection.example/test', {
      resolver: async () => [{ address: '127.0.0.1', family: 4 }],
      _dangerouslyAllowLocalhostForTesting: true,
      _portOverrideForTesting: port,
    });

    assert.equal(res.statusCode, 200);
    assert.equal(serverReceivedHostHeader, 'verified-connection.example');
    assert.equal(serverReceivedUserAgent, 'CyberLens-Scanner/1.0');
    assert.ok(res.bodySnippet.includes('real-connection-verified'));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

// ---------------------------------------------------------------------------
// 6. Integration: POST /api/investigations blocks SSRF and stores nothing
// ---------------------------------------------------------------------------

test('SSRF: POST /api/investigations with http://127.0.0.1/ returns 400 SSRF_BLOCKED and stores nothing', async () => {
  await repository.clear();

  const req = {
    body: {
      type: 'url',
      target: 'http://127.0.0.1/secret-admin',
    },
  };
  const res = createMockRes();

  let capturedError = null;
  await createInvestigation(req, res, (err) => {
    capturedError = err;
  });

  assert.ok(capturedError, 'createInvestigation should pass error to next()');
  assert.equal(capturedError.code, ERROR_CODES.SSRF_BLOCKED);
  assert.equal(capturedError.status, 400);

  // Verify that NOTHING was stored in the repository
  const allRecords = await repository.listInvestigations();
  assert.equal(allRecords.length, 0, 'No investigation record must be stored on SSRF failure');
});

