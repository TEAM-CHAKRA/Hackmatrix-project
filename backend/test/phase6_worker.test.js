import test from 'node:test';
import assert from 'node:assert/strict';
import { repository } from '../src/store/repository.js';
import { createInvestigation, getInvestigation } from '../src/controllers/investigationController.js';
import { investigationQueue, InvestigationQueue } from '../src/jobs/investigationQueue.js';
import { ERROR_CODES } from '../src/config/constants.js';
import { env } from '../src/config/env.js';

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

const originalGsbKey = env.GOOGLE_SAFE_BROWSING_API_KEY;

test.beforeEach(async () => {
  await repository.clear();
  investigationQueue.clear();
  // These flows mock GSB responses, so the provider must count as configured.
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'test-gsb-key';
});

test.afterEach(() => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = originalGsbKey;
});

test('Phase 6: Full Flow - POST -> 202 -> poll until completed with single DNS resolution', async () => {
  let resolverCallCount = 0;
  const mockResolver = async () => {
    resolverCallCount++;
    return [{ address: '93.184.216.34', family: 4 }];
  };

  // Mock fetch function returning clean check responses
  const mockFetch = async (url) => {
    const urlStr = String(url);
    if (urlStr.includes('safebrowsing.googleapis.com')) {
      return { ok: true, json: async () => ({}) }; // clean: no matches
    }
    if (urlStr.includes('urlhaus-api.abuse.ch')) {
      return { ok: true, json: async () => ({ query_status: 'no_results' }) };
    }
    if (urlStr.includes('crt.sh')) {
      return {
        ok: true,
        json: async () => [
          { entry_timestamp: '2026-01-01T00:00:00Z', not_before: '2026-01-01T00:00:00Z' },
        ],
      };
    }
    if (urlStr.includes('rdap.org')) {
      return {
        ok: true,
        json: async () => ({
          events: [{ eventAction: 'registration', eventDate: '2020-01-01T00:00:00Z' }],
          entities: [],
        }),
      };
    }
    // Gemini AI mock response
    if (urlStr.includes('generativelanguage.googleapis.com')) {
      return {
        ok: true,
        json: async () => ({
          candidates: [
            {
              content: {
                parts: [
                  {
                    text: JSON.stringify({
                      summary: 'The target domain was analyzed and found to be safe.',
                      keyPoints: ['No threat intelligence listings', 'Valid TLS certificate'],
                      recommendations: ['Maintain current security headers'],
                      limitations: ['Analysis is point-in-time'],
                    }),
                  },
                ],
              },
            },
          ],
        }),
      };
    }
    return { ok: true, json: async () => ({}) };
  };

  const mockRequestFn = async () => ({
    statusCode: 200,
    headers: {
      'strict-transport-security': 'max-age=31536000',
      'content-security-policy': "default-src 'self'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
    },
    redirectChain: [{ url: 'https://example.com/', statusCode: 200, suspicious: false }],
  });

  const mockTlsConnect = (options, callback) => {
    const socket = {
      authorized: true,
      authorizationError: null,
      destroy: () => {},
      getPeerCertificate: () => ({
        valid_from: 'Jan 1 00:00:00 2026 GMT',
        valid_to: 'Jan 1 00:00:00 2027 GMT',
        subject: { CN: 'example.com' },
        issuer: { CN: 'DigiCert Global Root G3' },
        subjectaltname: 'DNS:example.com',
        bits: 256,
        asn1Curve: 'prime256v1',
        sigalg: 'ecdsa-with-SHA384',
      }),
      on: () => {},
    };
    process.nextTick(callback);
    return socket;
  };

  const req = {
    app: {
      locals: {
        resolver: mockResolver,
        fetchFn: mockFetch,
        requestFn: mockRequestFn,
        tlsConnectFn: mockTlsConnect,
        _dangerouslyAllowLocalhostForTesting: true,
      },
    },
    body: {
      type: 'url',
      target: 'https://example.com',
    },
  };
  const res = createMockRes();

  // 1. POST /api/investigations
  await createInvestigation(req, res, (err) => {
    if (err) throw err;
  });

  assert.equal(res.statusCode, 202);
  assert.equal(res.body.success, true);
  assert.equal(res.body.status, 'processing');
  const investigationId = res.body.investigationId;
  assert.ok(investigationId);

  // 2. Poll until completed (drain worker queue)
  await investigationQueue.drain();

  // 3. GET /api/investigations/:id
  const getReq = { params: { id: investigationId } };
  const getRes = createMockRes();
  await getInvestigation(getReq, getRes, (err) => {
    if (err) throw err;
  });

  assert.equal(getRes.statusCode, 200);
  assert.equal(getRes.body.success, true);
  const report = getRes.body.report;

  // Assert report status and timestamps
  assert.equal(report.status, 'completed');
  assert.ok(report.completedAt);
  assert.ok(report.analyzedAt);
  assert.ok(!isNaN(new Date(report.analyzedAt).getTime()), 'analyzedAt must be a valid ISO date');
  assert.ok(!isNaN(new Date(report.completedAt).getTime()), 'completedAt must be a valid ISO date');

  // Assert DNS resolution count: exactly once for whole flow
  assert.equal(resolverCallCount, 1, 'Resolver must be called exactly once per investigation');

  // Assert stepper order and statuses
  const expectedSteps = ['submission', 'investigation', 'threat_intel', 'tls_security', 'risk_report'];
  assert.deepEqual(
    report.steps.map((s) => s.key),
    expectedSteps,
    'Step order must match expected sequence'
  );
  for (const step of report.steps) {
    assert.equal(step.status, 'completed', `Step "${step.key}" must be completed`);
  }

  // Assert check IDs
  const checkIds = report.checks.map((c) => c.id);
  assert.deepEqual(checkIds, ['gsb', 'urlhaus', 'domain', 'tls', 'ct', 'headers']);

  // Assert classification and score
  assert.equal(report.classification, 'low_risk');
  assert.equal(report.heuristicScore, 0);
  assert.equal(report.confidence, 'high');
  assert.equal(report.coverage.completed, 6);

  // Assert every finding has a valid source
  assert.ok(report.findings.length > 0, 'Report must contain findings');
  for (const finding of report.findings) {
    assert.ok(finding.source, `Finding ${finding.id} must have a source`);
    assert.equal(typeof finding.source, 'string');
    assert.ok(finding.source.length > 0);
  }

  // Assert job internals and resolved IPs are NOT exposed
  assert.equal(report.targetRaw, undefined);
  assert.equal(report.resolvedIp, undefined);
  assert.equal(report.validatedIp, undefined);
  assert.equal(report.canonicalSnapshot, undefined);
});

test('Phase 6: Live Stepper and Partial Checks during processing', async () => {
  let finishGsb;
  const gsbHoldPromise = new Promise((resolve) => {
    finishGsb = resolve;
  });

  // Mock fetch that holds one check so we can inspect partial checks during processing
  const mockFetch = async (url) => {
    const urlStr = String(url);
    if (urlStr.includes('safebrowsing.googleapis.com')) {
      await gsbHoldPromise;
      return { ok: true, json: async () => ({}) };
    }
    if (urlStr.includes('urlhaus-api.abuse.ch')) {
      return { ok: true, json: async () => ({ query_status: 'no_results' }) };
    }
    if (urlStr.includes('crt.sh')) {
      return { ok: true, json: async () => [] };
    }
    return { ok: true, json: async () => ({}) };
  };

  const req = {
    app: {
      locals: {
        resolver: async () => [{ address: '93.184.216.34', family: 4 }],
        fetchFn: mockFetch,
        requestFn: async () => ({ statusCode: 200, headers: {}, redirectChain: [] }),
        tlsConnectFn: (opt, cb) => {
          process.nextTick(cb);
          return { destroy: () => {}, getPeerCertificate: () => ({ subject: { CN: 'test.example' } }), on: () => {} };
        },
      },
    },
    body: { type: 'url', target: 'https://test.example' },
  };
  const res = createMockRes();

  await createInvestigation(req, res, () => {});
  const invId = res.body.investigationId;

  // Let initial microtasks execute so fast checks finish while GSB is held
  await new Promise((r) => setTimeout(r, 40));

  const getRes = createMockRes();
  await getInvestigation({ params: { id: invId } }, getRes, () => {});

  assert.equal(getRes.body.report.status, 'processing');
  assert.ok(getRes.body.report.steps.length === 5);
  // Some checks finished (e.g. urlhaus, domain) while GSB is still held
  assert.ok(Array.isArray(getRes.body.report.checks));

  // Release held GSB check
  finishGsb();
  await investigationQueue.drain();

  // Verify completed after release
  const finalRes = createMockRes();
  await getInvestigation({ params: { id: invId } }, finalRes, () => {});
  assert.equal(finalRes.body.report.status, 'completed');
});

test('Phase 6: A throwing check becomes status "error" and investigation still completes', async () => {
  const mockFetch = async (url) => {
    const urlStr = String(url);
    if (urlStr.includes('crt.sh') || urlStr.includes('certspotter')) {
      throw new Error('crt.sh network connection failed');
    }
    if (urlStr.includes('safebrowsing.googleapis.com')) {
      return { ok: true, json: async () => ({}) };
    }
    if (urlStr.includes('urlhaus-api.abuse.ch')) {
      return { ok: true, json: async () => ({ query_status: 'no_results' }) };
    }
    return { ok: true, json: async () => ({}) };
  };

  const req = {
    app: {
      locals: {
        resolver: async () => [{ address: '93.184.216.34', family: 4 }],
        fetchFn: mockFetch,
        requestFn: async () => ({ statusCode: 200, headers: {}, redirectChain: [] }),
        tlsConnectFn: (opt, cb) => {
          process.nextTick(cb);
          return { destroy: () => {}, getPeerCertificate: () => ({ subject: { CN: 'error-test.example' } }), on: () => {} };
        },
      },
    },
    body: { type: 'url', target: 'https://error-test.example' },
  };
  const res = createMockRes();

  await createInvestigation(req, res, () => {});
  const invId = res.body.investigationId;
  await investigationQueue.drain();

  const getRes = createMockRes();
  await getInvestigation({ params: { id: invId } }, getRes, () => {});

  assert.equal(getRes.body.report.status, 'completed');
  const ctCheck = getRes.body.report.checks.find((c) => c.id === 'ct');
  assert.ok(ctCheck);
  assert.equal(ctCheck.status, 'error');
  // An error check does not count towards completed coverage (5/6)
  assert.equal(getRes.body.report.coverage.completed, 5);
});

test('Phase 6: Uncaught pipeline failure marks status "failed", running step "failed", remaining "skipped"', async () => {
  const customQueue = new InvestigationQueue({ maxConcurrency: 1 });

  // Create an initial record directly
  await repository.createInvestigation({
    id: 'INV-TEST-FAIL-001',
    type: 'url',
    status: 'processing',
    target: { display: 'https://fatal.example' },
    steps: [
      { key: 'submission', label: 'Submission', status: 'completed' },
      { key: 'investigation', label: 'Investigation', status: 'running' },
      { key: 'threat_intel', label: 'Threat Intel', status: 'pending' },
      { key: 'tls_security', label: 'TLS Security', status: 'pending' },
      { key: 'risk_report', label: 'Risk Report', status: 'pending' },
    ],
    checks: [],
  });

  // Inject a job whose execution throws an uncaught error
  customQueue._executeInvestigation = async () => {
    throw new Error('Fatal out-of-memory or internal driver fault at /internal/lib/driver.sys');
  };

  customQueue.enqueue({
    investigationId: 'INV-TEST-FAIL-001',
    type: 'url',
  });

  await customQueue.drain();

  const getRes = createMockRes();
  await getInvestigation({ params: { id: 'INV-TEST-FAIL-001' } }, getRes, () => {});

  assert.equal(getRes.body.report.status, 'failed');
  assert.ok(getRes.body.report.error);
  // Safe message: never leak stack traces or internal paths
  assert.equal(
    getRes.body.report.error.message,
    'Investigation processing failed. The target could not be assessed.'
  );

  const steps = getRes.body.report.steps;
  assert.equal(steps.find((s) => s.key === 'submission').status, 'completed');
  assert.equal(steps.find((s) => s.key === 'investigation').status, 'failed');
  assert.equal(steps.find((s) => s.key === 'threat_intel').status, 'skipped');
  assert.equal(steps.find((s) => s.key === 'tls_security').status, 'skipped');
  assert.equal(steps.find((s) => s.key === 'risk_report').status, 'skipped');
});

test('Phase 6: Concurrency limit (e.g. maxConcurrency 2) enforces FIFO execution and prunes finished jobs', async () => {
  const concurrencyQueue = new InvestigationQueue({ maxConcurrency: 2, timeoutMs: 5000 });
  const executionOrder = [];
  let activeCount = 0;
  let maxObservedActive = 0;

  concurrencyQueue._executeInvestigation = async (job) => {
    activeCount++;
    maxObservedActive = Math.max(maxObservedActive, activeCount);
    executionOrder.push(`start-${job.investigationId}`);

    // Wait a brief period
    await new Promise((r) => setTimeout(r, 20));

    activeCount--;
    executionOrder.push(`finish-${job.investigationId}`);
  };

  // Enqueue 4 jobs in order 1, 2, 3, 4
  concurrencyQueue.enqueue({ investigationId: 'job-1', type: 'url' });
  concurrencyQueue.enqueue({ investigationId: 'job-2', type: 'url' });
  concurrencyQueue.enqueue({ investigationId: 'job-3', type: 'url' });
  concurrencyQueue.enqueue({ investigationId: 'job-4', type: 'url' });

  await concurrencyQueue.drain();

  // Max observed active jobs must not exceed maxConcurrency (2)
  assert.ok(maxObservedActive <= 2, `Max active jobs (${maxObservedActive}) must not exceed concurrency limit (2)`);

  // First 2 jobs start first (FIFO)
  assert.ok(executionOrder.indexOf('start-job-1') < executionOrder.indexOf('start-job-3'));
  assert.ok(executionOrder.indexOf('start-job-2') < executionOrder.indexOf('start-job-4'));

  // Ensure running set and queue are empty (no memory leak)
  assert.equal(concurrencyQueue.running.size, 0);
  assert.equal(concurrencyQueue.queue.length, 0);
});

test('Phase 6: Overall job timeout aborts long-running job and marks status "failed"', async () => {
  const timeoutQueue = new InvestigationQueue({ maxConcurrency: 1, timeoutMs: 30 }); // 30ms timeout

  await repository.createInvestigation({
    id: 'INV-TIMEOUT-TEST-001',
    type: 'url',
    status: 'processing',
    target: { display: 'https://hanging.example' },
    steps: [
      { key: 'submission', label: 'Submission', status: 'completed' },
      { key: 'investigation', label: 'Investigation', status: 'running' },
      { key: 'threat_intel', label: 'Threat Intel', status: 'pending' },
      { key: 'tls_security', label: 'TLS Security', status: 'pending' },
      { key: 'risk_report', label: 'Risk Report', status: 'pending' },
    ],
    checks: [],
  });

  // Inject a hanging job that never resolves
  timeoutQueue._executeInvestigation = async () => {
    await new Promise((resolve) => setTimeout(resolve, 5000));
  };

  timeoutQueue.enqueue({
    investigationId: 'INV-TIMEOUT-TEST-001',
    type: 'url',
  });

  await timeoutQueue.drain();

  const getRes = createMockRes();
  await getInvestigation({ params: { id: 'INV-TIMEOUT-TEST-001' } }, getRes, () => {});

  assert.equal(getRes.body.report.status, 'failed');
  assert.ok(getRes.body.report.error.message.includes('timed out'));
});

test('Phase 6 + Phase 4: message investigation completes with 4 checks, tls_security skipped, raw text dropped', async () => {
  const content = 'Your debit card has been blocked due to suspicious activity. Verify now at http://secure.example';
  const req = {
    app: { locals: { fetchFn: async () => ({ ok: true, status: 200, json: async () => ({ matches: [], query_status: 'no_results' }) }) } },
    body: { type: 'message', content },
  };
  const res = createMockRes();

  await createInvestigation(req, res, () => {});
  assert.equal(res.statusCode, 202);
  const msgInvId = res.body.investigationId;

  await investigationQueue.drain();

  const getRes = createMockRes();
  await getInvestigation({ params: { id: msgInvId } }, getRes, () => {});
  const report = getRes.body.report;

  assert.equal(report.status, 'completed');
  assert.deepEqual(report.checks.map((c) => c.id).sort(), ['indicators', 'links', 'tactics', 'threat_intel']);
  assert.equal(report.coverage.total, 4);
  assert.equal(report.steps.find((s) => s.key === 'tls_security').status, 'skipped');
  for (const key of ['submission', 'investigation', 'threat_intel', 'risk_report']) {
    assert.equal(report.steps.find((s) => s.key === key).status, 'completed', key);
  }
  assert.ok(report.message.highlights.length > 0);
  for (const h of report.message.highlights) assert.equal(content.slice(h.start, h.end), h.phrase);
  assert.deepEqual(report.message.indicators.urls, ['http://secure.example/']);

  const stored = await repository.getInvestigation(msgInvId);
  assert.equal(stored.targetRaw, null, 'raw message text is not kept after analysis');
  assert.ok(!JSON.stringify(report).includes('suspicious activity'), 'report never echoes the raw text');
});

test('Phase 6: Job timeout safety - slow job completing after timeout leaves record "failed" with no late partial writes', async () => {
  const shortTimeoutQueue = new InvestigationQueue({ maxConcurrency: 1, timeoutMs: 40 });

  // Mock fetch simulating slow check that finishes in 120ms (well past 40ms timeout)
  const slowFetch = async (url) => {
    const urlStr = String(url);
    if (urlStr.includes('safebrowsing.googleapis.com')) {
      await new Promise((r) => setTimeout(r, 120));
      return { ok: true, json: async () => ({}) };
    }
    return { ok: true, json: async () => ({}) };
  };

  const initialRecord = {
    id: 'INV-TIMEOUT-LATE-001',
    type: 'url',
    status: 'processing',
    target: { display: 'https://late-finish.example', host: 'late-finish.example' },
    steps: [
      { key: 'submission', label: 'Submission', status: 'completed' },
      { key: 'investigation', label: 'Investigation', status: 'running' },
      { key: 'threat_intel', label: 'Threat Intel', status: 'pending' },
      { key: 'tls_security', label: 'TLS Security', status: 'pending' },
      { key: 'risk_report', label: 'Risk Report', status: 'pending' },
    ],
    checks: [],
    createdAt: new Date().toISOString(),
  };

  await repository.createInvestigation(initialRecord);

  shortTimeoutQueue.enqueue({
    investigationId: 'INV-TIMEOUT-LATE-001',
    type: 'url',
    target: 'https://late-finish.example',
    validatedIp: '93.184.216.34',
    family: 4,
    addresses: ['93.184.216.34'],
    fetchFn: slowFetch,
    requestFn: async () => ({ statusCode: 200, headers: {}, redirectChain: [] }),
    tlsConnectFn: (opt, cb) => {
      process.nextTick(cb);
      return { destroy: () => {}, getPeerCertificate: () => ({ subject: { CN: 'late-finish.example' } }), on: () => {} };
    },
    _dangerouslyAllowLocalhostForTesting: true,
  });

  // Wait for worker timeout to trigger and queue to drain from runner perspective
  await shortTimeoutQueue.drain();

  // Verify immediately after timeout: status is "failed"
  const recordAtTimeout = await repository.getInvestigation('INV-TIMEOUT-LATE-001');
  assert.equal(recordAtTimeout.status, 'failed');
  assert.ok(recordAtTimeout.error?.message?.includes('timed out'));

  // Wait past the 120ms slow fetch completion to ensure background pipeline doesn't overwrite
  await new Promise((r) => setTimeout(r, 140));

  // Verify record remains failed and no late partial writes overwrite classification or score
  const recordAfterWork = await repository.getInvestigation('INV-TIMEOUT-LATE-001');
  assert.equal(recordAfterWork.status, 'failed');
  assert.equal(recordAfterWork.classification, undefined);
  assert.equal(recordAfterWork.heuristicScore, undefined);
  assert.equal(recordAfterWork.score, undefined);
  assert.equal(recordAfterWork.report, undefined);
  assert.ok(recordAfterWork.error?.message?.includes('timed out'));
});

test('Phase 6: Gemini failure/timeout leaves investigation "completed" with explanation.source "template"', async () => {
  const mockFetch = async (url) => {
    const urlStr = String(url);
    if (urlStr.includes('generativelanguage.googleapis.com')) {
      // Simulate Gemini outage or timeout error
      return {
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        text: async () => 'Gemini temporarily unavailable',
      };
    }
    if (urlStr.includes('safebrowsing.googleapis.com')) {
      return { ok: true, json: async () => ({}) };
    }
    if (urlStr.includes('urlhaus-api.abuse.ch')) {
      return { ok: true, json: async () => ({ query_status: 'no_results' }) };
    }
    if (urlStr.includes('crt.sh')) {
      return { ok: true, json: async () => [] };
    }
    if (urlStr.includes('rdap.org')) {
      return { ok: true, json: async () => ({ events: [{ eventAction: 'registration', eventDate: '2020-01-01T00:00:00Z' }] }) };
    }
    return { ok: true, json: async () => ({}) };
  };

  const req = {
    app: {
      locals: {
        resolver: async () => [{ address: '93.184.216.34', family: 4 }],
        fetchFn: mockFetch,
        requestFn: async () => ({ statusCode: 200, headers: {}, redirectChain: [] }),
        tlsConnectFn: (opt, cb) => {
          process.nextTick(cb);
          return {
            authorized: true,
            destroy: () => {},
            getPeerCertificate: () => ({
              valid_from: 'Jan 1 00:00:00 2026 GMT',
              valid_to: 'Jan 1 00:00:00 2027 GMT',
              subject: { CN: 'gemini-fallback.example' },
              issuer: { CN: 'DigiCert Global Root G3' },
              bits: 256,
            }),
            on: () => {},
          };
        },
        _dangerouslyAllowLocalhostForTesting: true,
      },
    },
    body: {
      type: 'url',
      target: 'https://gemini-fallback.example',
    },
  };

  const res = createMockRes();
  await createInvestigation(req, res, () => {});
  const invId = res.body.investigationId;

  await investigationQueue.drain();

  const getRes = createMockRes();
  await getInvestigation({ params: { id: invId } }, getRes, () => {});

  assert.equal(getRes.statusCode, 200);
  assert.equal(getRes.body.report.status, 'completed');
  assert.equal(getRes.body.report.explanation.source, 'template');
  assert.ok(getRes.body.report.explanation.summary);
  assert.ok(Array.isArray(getRes.body.report.explanation.keyPoints));
  assert.ok(getRes.body.report.explanation.keyPoints.length > 0);
});

test('Phase 6: GET response for processing, completed, and failed contains no resolved IPs, job internals, canonical snapshots or API keys', async () => {
  const secretKey = 'AIzaSyFakeSecretKeyForTesting12345';
  const testIp = '198.51.100.42';

  // 1. Processing state
  await repository.createInvestigation({
    id: 'INV-LEAK-PROC-001',
    type: 'url',
    status: 'processing',
    targetRaw: 'https://security-leak-test.example',
    target: { display: 'https://security-leak-test.example', host: 'security-leak-test.example' },
    steps: [
      { key: 'submission', label: 'Submission', status: 'completed' },
      { key: 'investigation', label: 'Investigation', status: 'running' },
      { key: 'threat_intel', label: 'Threat Intel', status: 'pending' },
      { key: 'tls_security', label: 'TLS Security', status: 'pending' },
      { key: 'risk_report', label: 'Risk Report', status: 'pending' },
    ],
    checks: [],
    createdAt: new Date().toISOString(),
  });

  const getProcRes = createMockRes();
  await getInvestigation({ params: { id: 'INV-LEAK-PROC-001' } }, getProcRes, () => {});
  assert.equal(getProcRes.body.report.status, 'processing');

  // 2. Completed state
  const compReq = {
    app: {
      locals: {
        resolver: async () => [{ address: testIp, family: 4 }],
        fetchFn: async () => ({ ok: true, json: async () => ({}) }),
        requestFn: async () => ({ statusCode: 200, headers: {}, redirectChain: [] }),
        tlsConnectFn: (opt, cb) => {
          process.nextTick(cb);
          return {
            destroy: () => {},
            getPeerCertificate: () => ({ subject: { CN: 'security-leak-test.example' } }),
            on: () => {},
          };
        },
        _dangerouslyAllowLocalhostForTesting: true,
      },
    },
    body: { type: 'url', target: 'https://security-leak-test.example' },
  };
  const compRes = createMockRes();
  await createInvestigation(compReq, compRes, () => {});
  const compId = compRes.body.investigationId;
  await investigationQueue.drain();

  const getCompRes = createMockRes();
  await getInvestigation({ params: { id: compId } }, getCompRes, () => {});
  assert.equal(getCompRes.body.report.status, 'completed');

  // 3. Failed state (a job whose pipeline throws)
  const failQueue = new InvestigationQueue({ maxConcurrency: 1 });
  failQueue._executeInvestigation = async () => {
    throw new Error(`boom with ${secretKey} at ${testIp}`);
  };
  const failId = 'INV-20261108-FA11FA11FA11FA11';
  await repository.createInvestigation({
    id: failId,
    type: 'url',
    status: 'processing',
    targetRaw: 'https://security-leak-test.example',
    target: { display: 'https://security-leak-test.example' },
    steps: [{ key: 'submission', label: 'Submission received', status: 'completed' }, { key: 'investigation', label: 'URL investigation', status: 'running' }],
    checks: [],
  });
  failQueue.enqueue({ investigationId: failId, type: 'url', validatedIp: testIp });
  await failQueue.drain();

  const getFailRes = createMockRes();
  await getInvestigation({ params: { id: failId } }, getFailRes, () => {});
  assert.equal(getFailRes.body.report.status, 'failed');

  // Assert on serialized JSON for all three states
  const forbiddenSubstrings = [
    '"resolvedIp"',
    '"validatedIp"',
    '"preValidatedIp"',
    '"allIps"',
    '"canonicalSnapshot"',
    '"targetRaw"',
    secretKey,
    testIp,
  ];

  for (const [stateName, response] of [
    ['processing', getProcRes],
    ['completed', getCompRes],
    ['failed', getFailRes],
  ]) {
    const serialized = JSON.stringify(response.body);
    for (const forbidden of forbiddenSubstrings) {
      assert.ok(
        !serialized.includes(forbidden),
        `GET response for state "${stateName}" must NOT contain forbidden substring: ${forbidden}`
      );
    }
  }
});

test('Phase 6: Default concurrency of 5 with 7 queued jobs: never more than 5 run simultaneously and all 7 complete', async () => {
  const queue = new InvestigationQueue();
  assert.equal(queue.maxConcurrency, 5);

  let currentRunning = 0;
  let maxObservedRunning = 0;
  let finishedCount = 0;

  queue._executeInvestigation = async () => {
    currentRunning++;
    if (currentRunning > maxObservedRunning) {
      maxObservedRunning = currentRunning;
    }

    // Simulate work taking 30ms
    await new Promise((resolve) => setTimeout(resolve, 30));

    currentRunning--;
    finishedCount++;
  };

  // Enqueue 7 jobs
  for (let i = 1; i <= 7; i++) {
    queue.enqueue({ investigationId: `job-concurrency-${i}`, type: 'url' });
  }

  await queue.drain();

  assert.equal(maxObservedRunning, 5, 'Peak concurrency must hit the maximum limit of 5');
  assert.equal(finishedCount, 7, 'All 7 queued jobs must complete');
  assert.equal(queue.running.size, 0, 'No jobs left in running set');
  assert.equal(queue.queue.length, 0, 'No jobs left in queue');
});
