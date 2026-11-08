import test from 'node:test';
import assert from 'node:assert/strict';
import { getHealth, _clearHealthCache, PROVIDER_URLS } from '../src/controllers/healthController.js';
import { env } from '../src/config/env.js';
import { blockchainService } from '../src/services/blockchainService.js';

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

const originalFetch = globalThis.fetch;
const originalEnvGsb = env.GOOGLE_SAFE_BROWSING_API_KEY;
const originalEnvGemini = env.GEMINI_API_KEY;
const originalEnvRpc = env.SEPOLIA_RPC_URL;
const originalEnvContract = env.REGISTRY_CONTRACT_ADDRESS;

const originalPing = blockchainService.ping;
const originalIsConfigured = blockchainService.isConfigured;

test.afterEach(() => {
  blockchainService.ping = originalPing;
  blockchainService.isConfigured = originalIsConfigured;
  globalThis.fetch = originalFetch;
  env.GOOGLE_SAFE_BROWSING_API_KEY = originalEnvGsb;
  env.GEMINI_API_KEY = originalEnvGemini;
  env.SEPOLIA_RPC_URL = originalEnvRpc;
  env.REGISTRY_CONTRACT_ADDRESS = originalEnvContract;
  _clearHealthCache();
});

test('Health: all providers up returns status ok and services ok', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'mock-gsb-key-12345';
  env.GEMINI_API_KEY = 'mock-gemini-key-12345';
  env.SEPOLIA_RPC_URL = 'https://sepolia.infura.io/v3/mock-key';
  env.REGISTRY_CONTRACT_ADDRESS = '0x1234567890123456789012345678901234567890';

  globalThis.fetch = async (url) => {
    return { ok: true, status: 200 };
  };
  // Phase 8: blockchain "ok" now requires a real RPC + contract-code check; stub it.
  blockchainService.isConfigured = () => true;
  blockchainService.ping = async () => true;

  const req = {};
  const res = createMockRes();

  await getHealth(req, res, () => {});

  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(res.body.success, true);
  assert.equal(res.body.status, 'ok');
  assert.deepEqual(res.body.services, {
    database: 'ok',
    googleSafeBrowsing: 'ok',
    urlhaus: 'ok',
    crtsh: 'ok',
    certspotter: 'ok',
    certificateLogs: 'ok',
    ai: 'ok',
    blockchain: 'ok',
  });
});

test('Health: one down (urlhaus fails) marks urlhaus unavailable and overall status degraded', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'mock-gsb-key';

  globalThis.fetch = async (url) => {
    if (url === PROVIDER_URLS.urlhaus) {
      throw new Error('Connection refused (mocked network down)');
    }
    return { ok: true, status: 200 };
  };

  const req = {};
  const res = createMockRes();

  await getHealth(req, res, () => {});

  assert.equal(res.body.success, true);
  assert.equal(res.body.status, 'degraded');
  assert.equal(res.body.services.urlhaus, 'unavailable');
  assert.equal(res.body.services.crtsh, 'ok');
  assert.equal(res.body.services.googleSafeBrowsing, 'ok');
  assert.equal(res.body.services.database, 'ok');
});

test('Health: provider timeout results in unavailable and degraded status', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'mock-gsb-key';

  globalThis.fetch = async (url) => {
    if (url === PROVIDER_URLS.crtsh) {
      const err = new Error('The operation was aborted due to timeout');
      err.name = 'AbortError';
      throw err;
    }
    return { ok: true, status: 200 };
  };

  const req = {};
  const res = createMockRes();

  await getHealth(req, res, () => {});

  assert.equal(res.body.success, true);
  // crt.sh down but its fallback (Cert Spotter) answers: certificate logs still covered.
  assert.equal(res.body.status, 'ok');
  assert.equal(res.body.services.crtsh, 'unavailable');
  assert.equal(res.body.services.certspotter, 'ok');
  assert.equal(res.body.services.certificateLogs, 'ok');
  assert.equal(res.body.services.urlhaus, 'ok');
});

test('Health: crt.sh AND Cert Spotter both down → certificate logs unavailable, degraded', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'mock-gsb-key';
  globalThis.fetch = async (url) => {
    if (url === PROVIDER_URLS.crtsh || url === PROVIDER_URLS.certspotter) throw new Error('down');
    return { ok: true, status: 200 };
  };
  const res = createMockRes();
  await getHealth({}, res, () => {});
  assert.equal(res.body.status, 'degraded');
  assert.equal(res.body.services.certificateLogs, 'unavailable');
});

test('Health: missing GOOGLE_SAFE_BROWSING_API_KEY is unavailable without network call', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = '';

  let gsbFetchAttempted = false;
  globalThis.fetch = async (url) => {
    if (url === PROVIDER_URLS.googleSafeBrowsing) {
      gsbFetchAttempted = true;
    }
    return { ok: true, status: 200 };
  };

  const req = {};
  const res = createMockRes();

  await getHealth(req, res, () => {});

  assert.equal(gsbFetchAttempted, false, 'Should not fetch Google Safe Browsing when key is empty');
  assert.equal(res.body.services.googleSafeBrowsing, 'unavailable');
  assert.equal(res.body.status, 'degraded');
});

test('Health: missing AI and Blockchain keys reports them as unavailable', async () => {
  env.GEMINI_API_KEY = '';
  env.SEPOLIA_RPC_URL = '';
  env.REGISTRY_CONTRACT_ADDRESS = '';

  globalThis.fetch = async () => ({ ok: true, status: 200 });

  const req = {};
  const res = createMockRes();

  await getHealth(req, res, () => {});

  assert.equal(res.body.services.ai, 'unavailable');
  assert.equal(res.body.services.blockchain, 'unavailable');
  assert.equal(res.body.services.database, 'ok');
});

test('Health: response never includes API keys, URLs, RPC addresses or error messages', async () => {
  const secretKey = 'super-secret-gsb-api-key-999';
  const secretRpc = 'https://sepolia.infura.io/v3/secret-project-id-888';
  const sensitiveErrorText = 'Internal DB connection failure detail stack';

  env.GOOGLE_SAFE_BROWSING_API_KEY = secretKey;
  env.SEPOLIA_RPC_URL = secretRpc;

  globalThis.fetch = async (url) => {
    throw new Error(sensitiveErrorText);
  };

  const req = {};
  const res = createMockRes();

  await getHealth(req, res, () => {});

  const serialized = JSON.stringify(res.body);

  assert.ok(!serialized.includes(secretKey), 'Must not leak GOOGLE_SAFE_BROWSING_API_KEY');
  assert.ok(!serialized.includes(secretRpc), 'Must not leak SEPOLIA_RPC_URL');
  assert.ok(!serialized.includes(sensitiveErrorText), 'Must not leak error details');
  assert.ok(!serialized.includes('http'), 'Must not include URLs in response body');
});

test('Health: caching prevents hammering providers within 30 seconds', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'mock-key';

  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls++;
    return { ok: true, status: 200 };
  };

  const req = {};
  const res1 = createMockRes();
  const res2 = createMockRes();

  await getHealth(req, res1, () => {});
  const callsAfterFirst = fetchCalls;
  assert.ok(callsAfterFirst > 0, 'Fetch should be called on first invocation');

  await getHealth(req, res2, () => {});
  assert.equal(fetchCalls, callsAfterFirst, 'Second call within 30s should be served from cache');
  assert.deepEqual(res1.body, res2.body);
});

