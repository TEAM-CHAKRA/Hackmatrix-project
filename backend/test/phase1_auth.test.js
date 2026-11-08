import test, { describe } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../src/app.js';
import { repository } from '../src/store/repository.js';
import { sessionStore } from '../src/services/auth/sessionStore.js';
import { authService } from '../src/services/auth/authService.js';
import { loadEnv, EnvError, env } from '../src/config/env.js';
import { _resetRateLimitsForTesting } from '../src/middleware/rateLimiter.js';

const ORIGIN = 'http://localhost:5173';
const COOKIE = env.SESSION_COOKIE_NAME;
const VALID_USER = Object.freeze({ fullName: 'Asha Rao', email: 'Asha.Rao@Example.com', password: 'Secur3-passphrase', acceptTerms: true });

test.beforeEach(async () => {
  await repository.clear();
  await _resetRateLimitsForTesting();
  sessionStore.available = true;
});

async function csrf(agent) {
  return (await agent.get('/api/auth/csrf').expect(200)).body.csrfToken;
}
async function register(agent, body = VALID_USER) {
  const t = await csrf(agent);
  return agent.post('/api/auth/register').set('X-CSRF-Token', t).send(body);
}
async function login(agent, email = VALID_USER.email, password = VALID_USER.password) {
  const t = await csrf(agent);
  return agent.post('/api/auth/login').set('X-CSRF-Token', t).send({ email, password });
}
function sessionCookie(res) {
  const raw = [].concat(res.headers['set-cookie'] || []).find((c) => c.startsWith(`${COOKIE}=`));
  return raw ? raw.split(';')[0] : null;
}

describe('Phase 1 — register', () => {
  test('creates an account, signs in, stores an Argon2id hash and returns a safe user', async () => {
    const agent = request.agent(app);
    const res = await register(agent);
    assert.equal(res.status, 201);
    assert.equal(res.body.user.email, 'asha.rao@example.com');
    assert.equal(res.body.user.role, 'user');
    assert.match(res.body.user.id, /^USR-[0-9a-f]{24}$/);
    assert.equal(res.body.user.passwordHash, undefined);
    assert.ok(res.body.csrfToken);
    const cookie = [].concat(res.headers['set-cookie']).find((c) => c.startsWith(`${COOKIE}=`));
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Lax/i);
    const stored = await repository.getUserByEmail('asha.rao@example.com');
    assert.match(stored.passwordHash, /^\$argon2id\$/);
    await agent.get('/api/auth/me').expect(200);
  });

  test('rejects missing fields, invalid emails and weak passwords', async () => {
    let res = await register(request.agent(app), {});
    assert.equal(res.status, 400);
    assert.equal(res.body.error.code, 'VALIDATION_ERROR');
    for (const k of ['fullName', 'email', 'password', 'acceptTerms']) assert.ok(res.body.error.details[k], k);
    for (const email of ['not-an-email', 'a@b', 'a b@example.com']) {
      res = await register(request.agent(app), { ...VALID_USER, email });
      assert.equal(res.status, 400);
      assert.ok(res.body.error.details.email);
    }
    await _resetRateLimitsForTesting();
    for (const password of ['short1', 'lettersonly', '1234567890', 'password123']) {
      res = await register(request.agent(app), { ...VALID_USER, password });
      assert.equal(res.status, 400);
      assert.ok(res.body.error.details.password, password);
    }
  });

  test('rejects a duplicate email regardless of case', async () => {
    await register(request.agent(app)).then((r) => assert.equal(r.status, 201));
    const res = await register(request.agent(app), { ...VALID_USER, email: ' ASHA.RAO@example.COM ' });
    assert.equal(res.status, 409);
    assert.equal(res.body.error.code, 'EMAIL_TAKEN');
  });

  test('blocks privilege escalation and mass assignment', async () => {
    for (const extra of [{ role: 'admin' }, { passwordHash: 'x' }, { id: 'USR-x' }, { isAdmin: true }]) {
      const res = await register(request.agent(app), { ...VALID_USER, ...extra });
      assert.equal(res.status, 400);
    }
    assert.equal(await repository.getUserByEmail('asha.rao@example.com'), null);
  });
});

describe('Phase 1 — login, session and logout', () => {
  test('login works; wrong password and unknown account get the same generic 401', async () => {
    await register(request.agent(app));
    const ok = await login(request.agent(app));
    assert.equal(ok.status, 200);
    assert.equal(ok.body.user.email, 'asha.rao@example.com');
    const wrong = await login(request.agent(app), VALID_USER.email, 'Wrong-passw0rd');
    const unknown = await login(request.agent(app), 'nobody@example.com', 'Wrong-passw0rd');
    assert.equal(wrong.status, 401);
    assert.equal(wrong.body.error.code, 'INVALID_CREDENTIALS');
    assert.deepEqual(wrong.body, unknown.body);
  });

  test('session ID is regenerated on login and the pre-login ID is not authenticated', async () => {
    await register(request.agent(app));
    const agent = request.agent(app);
    const pre = await agent.get('/api/auth/csrf');
    const preCookie = sessionCookie(pre);
    const res = await agent.post('/api/auth/login').set('X-CSRF-Token', pre.body.csrfToken).send({ email: VALID_USER.email, password: VALID_USER.password });
    const postCookie = sessionCookie(res);
    assert.ok(preCookie && postCookie);
    assert.notEqual(postCookie, preCookie);
    assert.notEqual(res.body.csrfToken, pre.body.csrfToken);
    await request(app).get('/api/auth/me').set('Cookie', preCookie).expect(401);
    await request(app).get('/api/auth/me').set('Cookie', postCookie).expect(200);
  });

  test('/me is 401 without a session, with a forged cookie, or after expiry', async () => {
    const r = await request(app).get('/api/auth/me').expect(401);
    assert.equal(r.body.error.code, 'NOT_AUTHENTICATED');
    await request(app).get('/api/auth/me').set('Cookie', `${COOKIE}=s%3Aforged.sig`).expect(401);
    const agent = request.agent(app);
    await register(agent);
    const past = new Date(Date.now() - 1000).toISOString();
    if (repository.kind === 'supabase') {
      await repository.db.from('cl_sessions').update({ expires_at: past }).not('sid', 'is', null);
    } else {
      for (const s of repository.sessions.values()) s.expiresAt = past;
    }
    await agent.get('/api/auth/me').expect(401);
  });

  test('logout destroys the session, clears the cookie and is idempotent', async () => {
    const agent = request.agent(app);
    const reg = await register(agent);
    const cookie = sessionCookie(reg);
    const out = await agent.post('/api/auth/logout').set('X-CSRF-Token', reg.body.csrfToken).expect(200);
    assert.match([].concat(out.headers['set-cookie']).join(';'), /Expires=Thu, 01 Jan 1970/);
    await agent.get('/api/auth/me').expect(401);
    await request(app).get('/api/auth/me').set('Cookie', cookie).expect(401);
    await agent.post('/api/auth/logout').expect(200);
    await request(app).post('/api/auth/logout').expect(200);
  });

  test('sessions are stored through the repository (ready for a persistent store)', async () => {
    const agent = request.agent(app);
    const reg = await register(agent);
    const sid = decodeURIComponent(sessionCookie(reg).split('=')[1]).slice(2).split('.')[0];
    const rec = await repository.getSession(sid);
    assert.equal(rec.userId, reg.body.user.id);
  });
});

describe('Phase 1 — CSRF and CORS', () => {
  test('state-changing auth requests need a valid token from the same session and a trusted origin', async () => {
    const agent = request.agent(app);
    const token = await csrf(agent);
    let res = await agent.post('/api/auth/register').send(VALID_USER);
    assert.equal(res.status, 403);
    assert.equal(res.body.error.code, 'CSRF_INVALID');
    await agent.post('/api/auth/login').set('X-CSRF-Token', 'wrong').send({ email: 'a@b.co', password: 'x' }).expect(403);
    await agent.post('/api/auth/register').set('Origin', 'https://evil.example').set('X-CSRF-Token', token).send(VALID_USER).expect(403);
    const other = await csrf(request.agent(app));
    await agent.post('/api/auth/register').set('X-CSRF-Token', other).send(VALID_USER).expect(403);
    await agent.post('/api/auth/register').set('Origin', ORIGIN).set('X-CSRF-Token', token).send(VALID_USER).expect(201);
  });

  test('logout of a signed-in session requires CSRF', async () => {
    const agent = request.agent(app);
    await register(agent);
    await agent.post('/api/auth/logout').expect(403);
    await agent.get('/api/auth/me').expect(200);
  });

  test('CORS allows only configured origins with credentials', async () => {
    const ok = await request(app).options('/api/auth/login').set('Origin', ORIGIN).set('Access-Control-Request-Method', 'POST');
    assert.equal(ok.headers['access-control-allow-origin'], ORIGIN);
    assert.equal(ok.headers['access-control-allow-credentials'], 'true');
    const bad = await request(app).options('/api/auth/login').set('Origin', 'https://evil.example').set('Access-Control-Request-Method', 'POST');
    assert.equal(bad.headers['access-control-allow-origin'], undefined);
  });
});

describe('Phase 1 — rate limiting', () => {
  test('failed logins are limited per IP', async () => {
    const agent = request.agent(app);
    const token = await csrf(agent);
    const attempt = () => agent.post('/api/auth/login').set('X-CSRF-Token', token).send({ email: 'x@example.com', password: 'Wrong-passw0rd' });
    for (let i = 0; i < env.AUTH_LOGIN_MAX_ATTEMPTS; i++) await attempt().expect(401);
    const res = await attempt().expect(429);
    assert.equal(res.body.error.code, 'RATE_LIMITED');
    assert.ok(res.headers['retry-after']);
  });

  test('registrations are limited per IP', async () => {
    for (let i = 0; i < env.AUTH_REGISTER_MAX_ATTEMPTS; i++) {
      const r = await register(request.agent(app), { ...VALID_USER, email: `u${i}@example.com` });
      assert.equal(r.status, 201);
    }
    const res = await register(request.agent(app), { ...VALID_USER, email: 'last@example.com' });
    assert.equal(res.status, 429);
  });
});

describe('Phase 1 — roles and admin bootstrap', () => {
  test('admin bootstrap creates an admin; registration can never create one', async () => {
    const admin = await authService.bootstrapAdmin({ email: 'Admin@Team.example', password: 'Adm1n-strong-pass', fullName: 'Ops' });
    assert.equal(admin.role, 'admin');
    const again = await authService.bootstrapAdmin({ email: 'admin@team.example', password: 'Adm1n-strong-pass' });
    assert.equal(again.id, admin.id, 'idempotent');
    await assert.rejects(() => authService.bootstrapAdmin({ email: 'x@team.example', password: 'weak' }), /too weak/);
    const res = await register(request.agent(app), { ...VALID_USER, email: 'admin@team.example' });
    assert.equal(res.status, 409);
  });

  test('requireRole: anonymous 401, user 403, admin allowed (community status endpoint)', async () => {
    await request(app).patch('/api/community/reports/CR-20261108-0000000000000000/status').send({ status: 'validated' }).expect(401);
    const user = request.agent(app);
    const reg = await register(user);
    const r = await user.patch('/api/community/reports/CR-20261108-0000000000000000/status').set('X-CSRF-Token', reg.body.csrfToken).send({ status: 'validated' });
    assert.equal(r.status, 403);
    assert.equal(r.body.error.code, 'FORBIDDEN');
    await authService.bootstrapAdmin({ email: 'admin@team.example', password: 'Adm1n-strong-pass' });
    const admin = request.agent(app);
    const li = await login(admin, 'admin@team.example', 'Adm1n-strong-pass');
    const a = await admin.patch('/api/community/reports/CR-20261108-0000000000000000/status').set('X-CSRF-Token', li.body.csrfToken).send({ status: 'validated' });
    assert.equal(a.status, 404, 'admin passes the role check; report does not exist');
  });
});

describe('Phase 1 — no secret leakage', () => {
  test('responses never contain password hashes; hashes and passwords never logged', async () => {
    const logs = [];
    const orig = { log: console.log, warn: console.warn, error: console.error, debug: console.debug };
    for (const k of Object.keys(orig)) console[k] = (...a) => logs.push(a.map(String).join(' '));
    try {
      const agent = request.agent(app);
      const bodies = [];
      const reg = await register(agent);
      bodies.push(reg.text);
      bodies.push((await agent.get('/api/auth/me')).text);
      bodies.push((await login(request.agent(app))).text);
      bodies.push((await login(request.agent(app), VALID_USER.email, 'Wrong-passw0rd')).text);
      const all = bodies.join('\n');
      assert.doesNotMatch(all, /passwordHash|\$argon2/);
      assert.ok(!all.includes(VALID_USER.password));
      const logText = logs.join('\n');
      assert.ok(!logText.includes(VALID_USER.password));
      assert.doesNotMatch(logText, /\$argon2/);
      assert.ok(!logText.includes(reg.body.csrfToken));
    } finally {
      Object.assign(console, orig);
    }
  });
});

describe('Phase 1 — health liveness/readiness and config', () => {
  test('live is always 200; ready reflects repository, session store and config', async () => {
    const live = await request(app).get('/api/health/live').expect(200);
    assert.equal(live.body.status, 'alive');
    const ready = await request(app).get('/api/health/ready').expect(200);
    assert.deepEqual(ready.body.checks, { repository: 'ok', session: 'ok', config: 'ok' });
    sessionStore.available = false;
    const down = await request(app).get('/api/health/ready').expect(503);
    assert.equal(down.body.checks.session, 'unavailable');
    assert.equal(down.body.error.code, 'NOT_READY');
    await request(app).get('/api/health/live').expect(200);
  });

  test('production fails fast on missing/unsafe settings and never echoes values', () => {
    assert.throws(() => loadEnv({ NODE_ENV: 'production' }), (err) => {
      assert.ok(err instanceof EnvError);
      const all = err.problems.join(' ');
      assert.match(all, /SESSION_SECRET is required/);
      assert.match(all, /FRONTEND_URL is required/);
      assert.match(all, /ALLOW_MEMORY_SESSION_STORE/);
      return true;
    });
    const secret = 'too-short-but-private';
    assert.throws(() => loadEnv({ NODE_ENV: 'production', SESSION_SECRET: secret, FRONTEND_URL: '*' }), (err) => {
      assert.ok(!err.message.includes(secret));
      return true;
    });
    assert.throws(
      () => loadEnv({ NODE_ENV: 'production', SESSION_SECRET: 'dev-cyberlens-session-secret-change-in-production-123456', FRONTEND_URL: 'https://a.example', ALLOW_MEMORY_SESSION_STORE: 'true' }),
      /published development default/
    );
    const ok = loadEnv({ NODE_ENV: 'production', SESSION_SECRET: 'x'.repeat(40), FRONTEND_URL: 'https://a.example,https://b.example', ALLOW_MEMORY_SESSION_STORE: 'true' });
    assert.equal(ok.SESSION_COOKIE_SECURE, true);
    assert.deepEqual(ok.FRONTEND_ORIGINS, ['https://a.example', 'https://b.example']);
  });

  test('security headers are set and the framework is hidden', async () => {
    const res = await request(app).get('/api/health/live');
    assert.equal(res.headers['x-powered-by'], undefined);
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.match(res.headers['content-security-policy'], /default-src 'none'/);
  });

  test('oversized and malformed bodies get the standard error format', async () => {
    const agent = request.agent(app);
    const token = await csrf(agent);
    const bad = await agent.post('/api/auth/login').set('X-CSRF-Token', token).set('Content-Type', 'application/json').send('{"email":');
    assert.equal(bad.status, 400);
    assert.equal(bad.body.success, false);
    const big = await agent.post('/api/auth/login').set('X-CSRF-Token', token).send({ email: 'a@b.co', password: 'x'.repeat(200 * 1024) });
    assert.equal(big.status, 413);
    assert.equal(big.body.error.code, 'PAYLOAD_TOO_LARGE');
  });
});
