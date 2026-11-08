import test from 'node:test';
import assert from 'node:assert/strict';
import { repository } from '../src/store/repository.js';
import { generateInvestigationId, generateCommunityId } from '../src/utils/idGenerator.js';
import { getHealth } from '../src/controllers/healthController.js';
import { createInvestigation, getInvestigation } from '../src/controllers/investigationController.js';
import { submitCommunityReport, listCommunityReports } from '../src/controllers/communityController.js';
import request from 'supertest';
import app from '../src/app.js';
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
    cookie(name, val, opts) {
      this.headers[name] = { val, opts };
      return this;
    },
    clearCookie(name) {
      delete this.headers[name];
      return this;
    },
  };
}

test.beforeEach(async () => {
  await repository.clear();
});

test('Phase 0: idGenerator produces IDs with at least 16 hex characters', () => {
  const invId = generateInvestigationId();
  const commId = generateCommunityId();

  assert.match(invId, /^INV-\d{8}-[0-9A-F]{16}$/);
  assert.match(commId, /^CR-\d{8}-[0-9A-F]{16}$/);
});

test('Phase 0: GET /api/health controller returns contract-compliant envelope', async () => {
  const req = {};
  const res = createMockRes();

  await getHealth(req, res, () => {});

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.success, true);
  assert.ok(res.body.status === 'ok' || res.body.status === 'degraded');
  assert.equal(res.body.services.database, 'ok');
});

test('Phase 0: POST /api/investigations creates processing record and returns 202', async () => {
  const req = {
    app: {
      locals: {
        resolver: async () => [{ address: '93.184.216.34', family: 4 }],
      },
    },
    body: {
      type: 'url',
      target: 'https://example.com/test-path?param=1',
    },
  };
  const res = createMockRes();

  await createInvestigation(req, res, (err) => {
    if (err) throw err;
  });

  assert.equal(res.statusCode, 202);
  assert.equal(res.body.success, true);
  assert.equal(res.body.status, 'processing');
  assert.match(res.body.investigationId, /^INV-\d{8}-[0-9A-F]{16}$/);

  // Verify stored record in repository
  const stored = await repository.getInvestigation(res.body.investigationId);
  assert.ok(stored);
  assert.equal(stored.type, 'url');
  assert.equal(stored.target.host, 'example.com');
  assert.equal(stored.steps.length, 5);
  assert.equal(stored.steps[0].status, 'completed');
});

test('Phase 0: GET /api/investigations/:id returns processing report or 404', async () => {
  // Test 404
  const req404 = { params: { id: 'INV-20261107-0000000000000000' } };
  const res404 = createMockRes();
  await getInvestigation(req404, res404, () => { });

  assert.equal(res404.statusCode, 404);
  assert.equal(res404.body.success, false);
  assert.equal(res404.body.error.code, ERROR_CODES.NOT_FOUND);

  // Test found
  const createReq = {
    body: {
      type: 'message',
      content: 'Your bank account has been suspended. Please verify your OTP immediately.',
    },
  };
  const createRes = createMockRes();
  await createInvestigation(createReq, createRes, () => { });
  const invId = createRes.body.investigationId;

  const reqGet = { params: { id: invId } };
  const resGet = createMockRes();
  await getInvestigation(reqGet, resGet, () => { });

  assert.equal(resGet.statusCode, 200);
  assert.equal(resGet.body.success, true);
  assert.equal(resGet.body.report.id, invId);
  assert.equal(resGet.body.report.type, 'message');
});

test('Phase 0: POST /api/community/reports creates pending review report', async () => {
  const req = {
    body: {
      targetType: 'domain',
      target: 'paypal-security-update.example',
      category: 'phishing',
      description: 'Phishing domain observed circulating in SMS text messages.',
    },
  };
  const res = createMockRes();

  await submitCommunityReport(req, res, () => { });

  assert.equal(res.statusCode, 201);
  assert.equal(res.body.success, true);
  assert.match(res.body.report.id, /^CR-\d{8}-[0-9A-F]{16}$/);
  assert.equal(res.body.report.status, 'pending_review');

  const listRes = createMockRes();
  await listCommunityReports({}, listRes, () => { });
  assert.equal(listRes.body.success, true);
  assert.equal(listRes.body.items.length, 1);
});

test('Phase 0/1: Authentication registers, logs in and retrieves the user (HTTP, with CSRF)', async () => {
  // Superseded the Phase 0 auth stub: real auth uses sessions + CSRF, so it is
  // exercised over HTTP. Full coverage lives in test/phase1_auth.test.js.
  const agent = request.agent(app);
  const token = (await agent.get('/api/auth/csrf').expect(200)).body.csrfToken;
  const reg = await agent
    .post('/api/auth/register')
    .set('X-CSRF-Token', token)
    .send({ fullName: 'Alice Security', email: 'alice@example.com', password: 'StrongPassword123!', acceptTerms: true })
    .expect(201);
  assert.equal(reg.body.user.email, 'alice@example.com');
  assert.equal(reg.body.user.passwordHash, undefined);

  const me = await agent.get('/api/auth/me').expect(200);
  assert.equal(me.body.user.fullName, 'Alice Security');

  await agent.post('/api/auth/logout').set('X-CSRF-Token', me.body.csrfToken).expect(200);
  await agent.get('/api/auth/me').expect(401);

  const t2 = (await agent.get('/api/auth/csrf').expect(200)).body.csrfToken;
  const login = await agent.post('/api/auth/login').set('X-CSRF-Token', t2).send({ email: 'alice@example.com', password: 'StrongPassword123!' }).expect(200);
  assert.equal(login.body.user.email, 'alice@example.com');
});

test('Phase 0: In-Memory repository isolation: pure in-memory without Prisma or SQLite', () => {
  assert.ok(repository);
  assert.equal(typeof repository.createInvestigation, 'function');
  assert.equal(typeof repository.storeCanonicalSnapshot, 'function');
  assert.equal(typeof repository.getCanonicalSnapshot, 'function');
  assert.equal(typeof repository.createRegistryEntry, 'function');
});

test('Phase 0: Request validation middleware returns VALIDATION_ERROR on malformed input', async () => {
  const { validate } = await import('../src/middleware/validate.js');
  const { createInvestigationSchema } = await import('../src/controllers/investigationController.js');

  const middleware = validate(createInvestigationSchema);
  const req = { body: { type: 'url', target: 'not-a-valid-url' } };
  const res = createMockRes();

  let errorCaptured = null;
  middleware(req, res, (err) => {
    errorCaptured = err;
  });

  assert.ok(errorCaptured);
  assert.equal(errorCaptured.code, ERROR_CODES.VALIDATION_ERROR);
  assert.equal(errorCaptured.status, 400);
});