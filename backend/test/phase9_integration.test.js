import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import request from 'supertest';
import app from '../src/app.js';
import { env } from '../src/config/env.js';
import { repository } from '../src/store/repository.js';
import { investigationQueue } from '../src/jobs/investigationQueue.js';
import { blockchainService } from '../src/services/blockchainService.js';
import { _resetRateLimitsForTesting } from '../src/middleware/rateLimiter.js';
import { _clearHealthCache } from '../src/controllers/healthController.js';

/**
 * Phase 9 — integration matrix over real HTTP (docs/backend.md §Phase 9).
 * External providers are mocked through app.locals; nothing touches the internet.
 */

const PHISH =
  'URGENT: Your SBI account has been suspended. Click http://sbi-kyc-update.example/verify within 24 hours. Enter your OTP and password.';

// GSB/URLhaus answer "clean" so threat_intel completes deterministically.
const cleanProviders = async (url) => {
  if (String(url).includes('safebrowsing')) return { ok: true, status: 200, json: async () => ({}) };
  return { ok: true, status: 200, json: async () => ({ query_status: 'no_results' }) };
};

const saved = { gsb: env.GOOGLE_SAFE_BROWSING_API_KEY, chain: env.REGISTRY_CONTRACT_ADDRESS };

test.beforeEach(async () => {
  await repository.clear();
  investigationQueue.clear();
  await _resetRateLimitsForTesting();
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'test-gsb-key';
  app.locals.fetchFn = cleanProviders;
});

test.afterEach(async () => {
  await investigationQueue.drain();
  env.GOOGLE_SAFE_BROWSING_API_KEY = saved.gsb;
  env.REGISTRY_CONTRACT_ADDRESS = saved.chain;
  blockchainService._reset();
  delete app.locals.fetchFn;
});

async function pollUntilDone(id, tries = 50) {
  for (let i = 0; i < tries; i++) {
    const res = await request(app).get(`/api/investigations/${id}`).expect(200);
    if (res.body.report.status !== 'processing') return res.body.report;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('investigation did not finish');
}

test('Phase 9: full message flow over HTTP — 202, live polling, completed report with 4 checks', async () => {
  const created = await request(app).post('/api/investigations').send({ type: 'message', content: PHISH }).expect(202);
  assert.equal(created.body.status, 'processing');
  assert.match(created.body.investigationId, /^INV-\d{8}-[0-9A-F]{16}$/);

  const first = await request(app).get(`/api/investigations/${created.body.investigationId}`).expect(200);
  assert.equal(first.body.report.steps.length, 5, 'stepper renders while processing');

  const report = await pollUntilDone(created.body.investigationId);
  assert.equal(report.status, 'completed');
  assert.equal(report.type, 'message');
  assert.deepEqual(report.checks.map((c) => c.id).sort(), ['indicators', 'links', 'tactics', 'threat_intel']);
  assert.equal(report.coverage.total, 4);
  assert.equal(report.coverage.completed, 4);
  assert.equal(report.classification, 'high_risk', 'language + link evidence, no provider match');
  assert.equal(report.registry.status, 'not_registered');
  for (const h of report.message.highlights) assert.equal(PHISH.slice(h.start, h.end), h.phrase);
  assert.ok(!JSON.stringify(report).includes('Enter your OTP and password'), 'raw text never returned');
});

test('Phase 9: lower-case IDs resolve to the same report (amendment 21)', async () => {
  const { body } = await request(app).post('/api/investigations').send({ type: 'message', content: PHISH }).expect(202);
  await investigationQueue.drain();
  const res = await request(app).get(`/api/investigations/${body.investigationId.toLowerCase()}`).expect(200);
  assert.equal(res.body.report.id, body.investigationId);
});

test('Phase 9: POST /api/investigations is rate limited after 30 requests per IP', async () => {
  for (let i = 0; i < 30; i++) {
    await request(app).post('/api/investigations').send({ type: 'message', content: `Hello team, meeting moved ${i}` }).expect(202);
  }
  const res = await request(app).post('/api/investigations').send({ type: 'message', content: 'one too many requests' }).expect(429);
  assert.equal(res.body.error.code, 'RATE_LIMITED');
  assert.ok(res.headers['retry-after']);
});

test('Phase 9: SSRF targets are rejected over HTTP before any record is created', async () => {
  const targets = [
    'http://127.0.0.1/',
    'http://169.254.169.254/latest/meta-data/',
    'http://[::1]/',
    'http://2130706433/',
    'http://0x7f.0.0.1/',
    'http://0177.0.0.1/',
    'http://10.0.0.5/admin',
    'http://example.com:8080/',
    'http://user:pass@example.com/',
    'file:///etc/passwd',
  ];
  for (const target of targets) {
    const res = await request(app).post('/api/investigations').send({ type: 'url', target });
    assert.equal(res.status, 400, target);
    assert.ok(['SSRF_BLOCKED', 'VALIDATION_ERROR'].includes(res.body.error.code), target);
  }
  assert.equal((await repository.listInvestigations()).length, 0);
});

test('Phase 9: invalid investigation payloads are rejected', async () => {
  for (const body of [{}, { type: 'message', content: 'short' }, { type: 'message', content: 'x'.repeat(5001) }, { type: 'url', target: 'not a url' }, { type: 'pdf' }]) {
    const res = await request(app).post('/api/investigations').send(body);
    assert.equal(res.status, 400, JSON.stringify(body).slice(0, 40));
    assert.equal(res.body.success, false);
  }
  await request(app).get('/api/investigations/INV-20261108-0000000000000000').expect(404);
});

test('Phase 9: registry endpoints never fake success when the chain is not configured', async () => {
  const { body } = await request(app).post('/api/investigations').send({ type: 'message', content: PHISH }).expect(202);
  await investigationQueue.drain();
  env.REGISTRY_CONTRACT_ADDRESS = '';
  blockchainService._reset();
  const reg = await request(app).post('/api/registry/register').send({ investigationId: body.investigationId });
  assert.equal(reg.status, 503);
  assert.equal(reg.body.error.code, 'CHAIN_UNAVAILABLE');
  const ver = await request(app).post('/api/registry/verify').send({ investigationId: body.investigationId });
  assert.equal(ver.status, 503);
  const feed = await request(app).get('/api/registry').expect(200);
  assert.deepEqual(feed.body.items, []);
});

test('Phase 9: public responses never leak secrets, raw targets or internal data', async () => {
  const secret = env.SESSION_SECRET;
  const { body } = await request(app).post('/api/investigations').send({ type: 'message', content: PHISH }).expect(202);
  await investigationQueue.drain();
  const agent = request.agent(app);
  const t = (await agent.get('/api/auth/csrf')).body.csrfToken;
  await agent.post('/api/community/reports').set('X-CSRF-Token', t).send({ targetType: 'url', target: 'https://evil.example/x?token=abc', category: 'phishing', description: 'Phishing page asking for card details.' }).expect(201);
  _clearHealthCache();
  const bodies = await Promise.all(
    ['/api/health', '/api/health/ready', '/api/registry', '/api/community/reports', `/api/investigations/${body.investigationId}`].map((p) => request(app).get(p))
  );
  const text = bodies.map((r) => r.text).join('\n');
  for (const banned of [secret, 'test-gsb-key', 'targetRaw', 'token=abc', 'validatedIp', 'passwordHash', 'canonicalSnapshot', 'stack']) {
    assert.ok(!text.includes(banned), `leaked: ${banned}`);
  }
});

test('Phase 9: unknown routes return the JSON error envelope', async () => {
  const res = await request(app).get('/api/does-not-exist').expect(404);
  assert.equal(res.body.success, false);
  assert.equal(res.body.error.code, 'NOT_FOUND');
});

test('Phase 9: repository stays database-free (no Prisma/SQLite artifacts)', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
  for (const banned of ['prisma', '@prisma/client', 'sqlite3', 'better-sqlite3']) assert.ok(!deps.includes(banned), banned);
  assert.ok(!fs.existsSync(path.join(root, 'prisma')));
});
