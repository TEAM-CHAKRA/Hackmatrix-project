import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../src/app.js';
import { repository } from '../src/store/repository.js';
import { authService } from '../src/services/auth/authService.js';
import { _resetRateLimitsForTesting } from '../src/middleware/rateLimiter.js';
import { displayTarget } from '../src/controllers/communityController.js';

const REPORT = {
  targetType: 'url',
  target: 'https://user:pw@sbi-kyc-update.example/verify?token=abc123',
  category: 'phishing',
  description: 'SMS claiming my SBI account was blocked, asking for OTP.',
};

test.beforeEach(async () => {
  await repository.clear();
  await _resetRateLimitsForTesting();
});

async function csrf(agent) {
  return (await agent.get('/api/auth/csrf').expect(200)).body.csrfToken;
}
async function submit(agent, body = REPORT) {
  const token = await csrf(agent); // fetch first: the agent attaches cookies when the request is created
  return agent.post('/api/community/reports').set('X-CSRF-Token', token).send(body);
}
async function signedInAgent(email) {
  const agent = request.agent(app);
  const t = await csrf(agent);
  const r = await agent.post('/api/auth/register').set('X-CSRF-Token', t).send({ fullName: 'Voter One', email, password: 'Secur3-passphrase', acceptTerms: true });
  assert.equal(r.status, 201);
  return { agent, token: r.body.csrfToken, user: r.body.user };
}
async function adminAgent() {
  await authService.bootstrapAdmin({ email: 'admin@team.example', password: 'Adm1n-strong-pass' });
  const agent = request.agent(app);
  const t = await csrf(agent);
  const r = await agent.post('/api/auth/login').set('X-CSRF-Token', t).send({ email: 'admin@team.example', password: 'Adm1n-strong-pass' });
  return { agent, token: r.body.csrfToken };
}

test('Phase 7: anonymous submission (CSRF + rate limit) returns 201 pending_review', async () => {
  const agent = request.agent(app);
  const res = await submit(agent);
  assert.equal(res.status, 201);
  assert.match(res.body.report.id, /^CR-\d{8}-[0-9A-F]{16}$/);
  assert.equal(res.body.report.status, 'pending_review');
  await request(app).post('/api/community/reports').send(REPORT).expect(403); // no CSRF token
});

test('Phase 7: target is validated per type', async () => {
  const cases = [
    ['url', 'not a url'],
    ['url', 'ftp://files.example/x'],
    ['domain', 'no_tld'],
    ['email', 'nobody'],
    ['phone', '12'],
  ];
  for (const [targetType, target] of cases) {
    const res = await submit(request.agent(app), { ...REPORT, targetType, target });
    assert.equal(res.status, 400, `${targetType}:${target}`);
    assert.equal(res.body.error.code, 'VALIDATION_ERROR');
  }
  await _resetRateLimitsForTesting();
  const short = await submit(request.agent(app), { ...REPORT, description: 'too short' });
  assert.equal(short.status, 400);
  const extra = await submit(request.agent(app), { ...REPORT, status: 'validated' });
  assert.equal(extra.status, 400, 'unknown fields rejected');
});

test('Phase 7: public listing shows a redacted target and never the raw target or submitter', async () => {
  await submit(request.agent(app));
  const res = await request(app).get('/api/community/reports').expect(200);
  const item = res.body.items[0];
  assert.equal(item.targetDisplay, 'sbi-kyc-update.example/verify');
  const text = JSON.stringify(res.body);
  for (const s of ['abc123', 'user:pw', 'token', 'submittedBy', 'voters']) assert.ok(!text.includes(s), s);
});

test('Phase 7: email and phone targets are masked for display', () => {
  assert.equal(displayTarget('email', 'Scammer@Fraud.example'), 's••••••@fraud.example');
  assert.equal(displayTarget('phone', '+91 98765 43210'), '+919••••••210');
  assert.equal(displayTarget('domain', 'Evil.Example'), 'evil.example');
});

test('Phase 7: one vote per voter, votes can switch, 3 voters → under_review', async () => {
  const id = (await submit(request.agent(app))).body.report.id;
  const a = await signedInAgent('a@example.com');
  let r = await a.agent.post(`/api/community/reports/${id}/vote`).set('X-CSRF-Token', a.token).send({ voteType: 'confirm' });
  assert.deepEqual(r.body.report.validation, { confirms: 1, disputes: 0 });
  r = await a.agent.post(`/api/community/reports/${id}/vote`).set('X-CSRF-Token', a.token).send({ voteType: 'confirm' });
  assert.deepEqual(r.body.report.validation, { confirms: 1, disputes: 0 }, 'repeat vote does not count twice');
  assert.equal(r.body.report.changed, false);
  r = await a.agent.post(`/api/community/reports/${id}/vote`).set('X-CSRF-Token', a.token).send({ voteType: 'dispute' });
  assert.deepEqual(r.body.report.validation, { confirms: 0, disputes: 1 }, 'switching moves the vote');

  const b = await signedInAgent('b@example.com');
  await b.agent.post(`/api/community/reports/${id}/vote`).set('X-CSRF-Token', b.token).send({ voteType: 'confirm' }).expect(200);
  const c = await signedInAgent('c@example.com');
  r = await c.agent.post(`/api/community/reports/${id}/vote`).set('X-CSRF-Token', c.token).send({ voteType: 'confirm' });
  assert.deepEqual(r.body.report.validation, { confirms: 2, disputes: 1 });
  assert.equal(r.body.report.status, 'under_review');

  // Anonymous voters are keyed by (hashed) IP: one vote from this address
  const anon = request.agent(app);
  const t = await csrf(anon);
  await anon.post(`/api/community/reports/${id}/vote`).set('X-CSRF-Token', t).send({ voteType: 'confirm' }).expect(200);
  r = await anon.post(`/api/community/reports/${id}/vote`).set('X-CSRF-Token', t).send({ voteType: 'confirm' });
  assert.equal(r.body.report.validation.confirms, 3);

  await request(app).post('/api/community/reports/CR-20261108-0000000000000000/vote').set('X-CSRF-Token', t).send({ voteType: 'confirm' });
  const missing = await anon.post('/api/community/reports/CR-20261108-0000000000000000/vote').set('X-CSRF-Token', t).send({ voteType: 'confirm' });
  assert.equal(missing.status, 404);
});

test('Phase 7: only admins change status; rejected reports disappear from the public list', async () => {
  const id = (await submit(request.agent(app))).body.report.id;
  const user = await signedInAgent('u@example.com');
  await user.agent.patch(`/api/community/reports/${id}/status`).set('X-CSRF-Token', user.token).send({ status: 'validated' }).expect(403);

  const admin = await adminAgent();
  const v = await admin.agent.patch(`/api/community/reports/${id}/status`).set('X-CSRF-Token', admin.token).send({ status: 'validated' });
  assert.equal(v.status, 200);
  assert.equal(v.body.report.status, 'validated');
  assert.ok((await repository.getCommunityReport(id)).validatedAt);

  await admin.agent.patch(`/api/community/reports/${id}/status`).set('X-CSRF-Token', admin.token).send({ status: 'rejected' }).expect(200);
  const pub = await request(app).get('/api/community/reports').expect(200);
  assert.equal(pub.body.items.length, 0);
  await request(app).get(`/api/community/reports/${id}`).expect(404);
  const adm = await admin.agent.get('/api/community/reports').expect(200);
  assert.equal(adm.body.items.length, 1, 'admins still see it');
  await admin.agent.patch(`/api/community/reports/${id}/status`).set('X-CSRF-Token', admin.token).send({ status: 'bogus' }).expect(400);
});

test('Phase 7: community reports never get a risk classification', async () => {
  await submit(request.agent(app));
  const res = await request(app).get('/api/community/reports').expect(200);
  assert.equal(res.body.items[0].classification, undefined);
});
