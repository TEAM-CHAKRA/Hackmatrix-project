import test from 'node:test';
import assert from 'node:assert/strict';
import { loadEnv, EnvError } from '../src/config/env.js';
import { classifySupabaseKey } from '../src/store/supabaseKey.js';
import { createRepository, MemoryRepository } from '../src/store/repository.js';
import { SupabaseRepository } from '../src/store/supabaseRepository.js';
import { explainDbError } from '../src/store/dbCheck.js';

const jwt = (payload) =>
  ['e30', Buffer.from(JSON.stringify(payload)).toString('base64url'), 'sig'].join('.');
const SERVICE = jwt({ role: 'service_role' });
const ANON = jwt({ role: 'anon' });
const URL = 'https://abcdefghijklmnop.supabase.co';

test('DB provider: memory by default, Supabase automatically when URL + secret key are set', () => {
  assert.equal(loadEnv({}).DB_PROVIDER, 'memory');
  const e = loadEnv({ SUPABASE_URL: `${URL}/`, SUPABASE_SERVICE_ROLE_KEY: SERVICE });
  assert.equal(e.DB_PROVIDER, 'supabase');
  assert.equal(e.SUPABASE_URL, URL, 'trailing slash removed');
  assert.equal(loadEnv({ SUPABASE_URL: `${URL}/rest/v1`, SUPABASE_SECRET_KEY: 'sb_secret_x' }).SUPABASE_KEY, 'sb_secret_x');
  assert.equal(loadEnv({ DB_PROVIDER: 'memory', SUPABASE_URL: URL, SUPABASE_SERVICE_ROLE_KEY: SERVICE }).DB_PROVIDER, 'memory');
});

test('DB provider: the public anon/publishable key is refused with a clear message', () => {
  for (const key of [ANON, 'sb_publishable_abc']) {
    assert.throws(
      () => loadEnv({ SUPABASE_URL: URL, SUPABASE_SERVICE_ROLE_KEY: key }),
      (err) => err instanceof EnvError && /anon\/publishable/.test(err.message) && !err.message.includes(key)
    );
  }
  assert.equal(classifySupabaseKey(SERVICE), 'secret');
  assert.equal(classifySupabaseKey('sb_secret_abc'), 'secret');
  assert.equal(classifySupabaseKey('garbage'), 'unknown');
});

test('DB provider: DB_PROVIDER=supabase without settings, or a bad URL, fails fast', () => {
  assert.throws(() => loadEnv({ DB_PROVIDER: 'supabase' }), /SUPABASE_URL is required[\s\S]*SUPABASE_SERVICE_ROLE_KEY is required/);
  assert.throws(() => loadEnv({ SUPABASE_URL: 'supabase.co/x', SUPABASE_SERVICE_ROLE_KEY: SERVICE }), /must look like https/);
});

test('DB provider: production no longer needs ALLOW_MEMORY_SESSION_STORE once Supabase is used', () => {
  const prod = {
    NODE_ENV: 'production',
    FRONTEND_URL: 'https://cyberlens.example',
    SESSION_SECRET: 'x'.repeat(48),
  };
  assert.throws(() => loadEnv(prod), /ALLOW_MEMORY_SESSION_STORE/);
  assert.equal(loadEnv({ ...prod, SUPABASE_URL: URL, SUPABASE_SERVICE_ROLE_KEY: SERVICE }).DB_PROVIDER, 'supabase');
});

test('DB provider: factory builds the right repository; Supabase clear() is locked', async () => {
  assert.ok(createRepository({ DB_PROVIDER: 'memory' }) instanceof MemoryRepository);
  const repo = createRepository({ DB_PROVIDER: 'supabase', SUPABASE_URL: URL, SUPABASE_KEY: SERVICE, NODE_ENV: 'production' });
  assert.ok(repo instanceof SupabaseRepository);
  assert.equal(repo.kind, 'supabase');
  await assert.rejects(() => repo.clear(), /disabled/);
});

test('DB check: errors are explained in plain words', () => {
  assert.match(explainDbError({ code: 'PGRST205', message: "Could not find the table 'public.cl_users'" }), /schema\.sql/);
  assert.match(explainDbError({ code: '42501', message: 'permission denied for table cl_users' }), /service_role/);
  assert.match(explainDbError({ message: 'Invalid API key' }), /key rejected/);
  assert.match(explainDbError({ message: 'TypeError: fetch failed' }), /cannot reach Supabase/);
});
