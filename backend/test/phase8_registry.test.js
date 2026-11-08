import test, { describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import request from 'supertest';
import { ethers } from 'ethers';
import app from '../src/app.js';
import { env } from '../src/config/env.js';
import { repository } from '../src/store/repository.js';
import { blockchainService } from '../src/services/blockchainService.js';
import { _clearHealthCache } from '../src/controllers/healthController.js';
import { _resetRateLimitsForTesting } from '../src/middleware/rateLimiter.js';
import { generateInvestigationId, generateCommunityId } from '../src/utils/idGenerator.js';
import {
  buildInvestigationSnapshot,
  buildCommunitySnapshot,
  canonicalize,
  computeHash,
  sha256Hex,
} from '../src/services/canonicalHasher.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const CONTRACTS = path.resolve(here, '..', '..', 'contracts');
const HARDHAT = path.join(CONTRACTS, 'node_modules', 'hardhat', 'internal', 'cli', 'bootstrap.js');
const ARTIFACT = path.join(CONTRACTS, 'artifacts', 'contracts', 'CyberlensRegistry.sol', 'CyberlensRegistry.json');
const PORT = 8547;
const RPC = `http://127.0.0.1:${PORT}`;
// Hardhat's well-known development account #0 (public test key, never use on a real network).
const DEV_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

function completedRecord(overrides = {}) {
  const id = generateInvestigationId();
  return {
    id,
    type: 'url',
    status: 'completed',
    targetRaw: 'https://paypa1-login.example/signin?token=secret',
    target: { display: 'https://paypa1-login.example/signin', host: 'paypa1-login.example' },
    steps: [{ key: 'submission', label: 'Submission received', status: 'completed' }],
    checks: [
      { id: 'gsb', status: 'match_found' },
      { id: 'urlhaus', status: 'unavailable' },
      { id: 'domain', status: 'completed' },
      { id: 'tls', status: 'completed' },
      { id: 'ct', status: 'error' },
      { id: 'headers', status: 'completed' },
    ],
    classification: 'confirmed_malicious',
    confidence: 'high',
    heuristicScore: 100,
    coverage: { completed: 4, total: 6, missing: ['urlhaus', 'ct'] },
    findings: [
      { id: 'f_gsb_1', title: 'Google Safe Browsing: SOCIAL_ENGINEERING', severity: 'critical', category: 'confirmed', source: 'Google Safe Browsing', checkId: 'gsb', evidence: { 'Threat type': 'SOCIAL_ENGINEERING' } },
      { id: 'f_typo_paypal', title: 'Look-alike of paypal', severity: 'high', category: 'heuristic', source: 'Domain analysis', checkId: 'domain', evidence: { Domain: 'paypa1-login.example' } },
    ],
    tls: { status: 'valid', hostnameMatch: true, distrust: { status: 'no_match' } },
    securityHeaders: { status: 'completed' },
    redirectChain: [{ url: 'https://paypa1-login.example/signin', statusCode: 200 }],
    explanation: { source: 'template', summary: 'x', keyPoints: [] },
    registry: { status: 'not_registered' },
    completedAt: '2026-11-08T05:00:00.000Z',
    analyzedAt: '2026-11-08T05:00:00.000Z',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
describe('Phase 8 — canonical snapshot and hashing (offline)', () => {
  test('deterministic: key order and excluded fields do not change the hash', () => {
    const rec = completedRecord();
    const a = computeHash(buildInvestigationSnapshot(rec));
    const shuffled = Object.fromEntries(Object.entries(rec).reverse());
    const noise = {
      ...rec,
      steps: [],
      registry: { status: 'registered' },
      createdAt: 'x',
      updatedAt: 'y',
      demo: true,
      targetRaw: 'changed',
      explanation: { summary: 'different words' },
      findings: rec.findings.map((f) => ({ ...f, evidence: { other: 1 }, description: 'changed' })).reverse(),
      checks: [...rec.checks].reverse(),
    };
    assert.equal(computeHash(buildInvestigationSnapshot(shuffled)).reportHash, a.reportHash);
    assert.equal(computeHash(buildInvestigationSnapshot(noise)).reportHash, a.reportHash);
    assert.equal(a.reportHash, sha256Hex(a.canonicalString));
    assert.match(a.reportHash, /^[0-9a-f]{64}$/);
    assert.equal(JSON.parse(a.canonicalString).canonicalVersion, 'cyberlens-report/v1');
  });

  test('security-relevant changes DO change the hash', () => {
    const rec = completedRecord();
    const base = computeHash(buildInvestigationSnapshot(rec)).reportHash;
    for (const change of [{ classification: 'low_risk' }, { heuristicScore: 10 }, { checks: rec.checks.map((c) => (c.id === 'gsb' ? { ...c, status: 'no_match' } : c)) }]) {
      assert.notEqual(computeHash(buildInvestigationSnapshot({ ...rec, ...change })).reportHash, base);
    }
  });

  test('snapshot excludes raw URL query, message text and transient fields', () => {
    const s = canonicalize(buildInvestigationSnapshot(completedRecord()));
    for (const banned of ['token=secret', 'targetRaw', '"steps"', '"registry"', '"demo"', '"status":"completed","steps', 'explanation']) {
      assert.ok(!s.includes(banned), banned);
    }
    const msg = completedRecord({
      type: 'message',
      targetRaw: 'Your OTP is 123456 send it now',
      message: { highlights: [{ start: 0, end: 4, phrase: 'Your', tactic: 'urgency' }], indicators: { urls: ['http://x.example/'], domains: [], emails: ['a@b.example'], phones: [] }, tactics: [{ key: 'otp_request', count: 1 }] },
    });
    const ms = canonicalize(buildInvestigationSnapshot(msg));
    assert.ok(!ms.includes('123456') && !ms.includes('a@b.example') && !ms.includes('x.example') && !ms.includes('phrase'));
    assert.match(ms, /"indicatorCounts"/);
  });

  test('only completed investigations can be snapshotted', () => {
    assert.throws(() => buildInvestigationSnapshot(completedRecord({ status: 'processing' })));
  });

  test('community snapshot uses its own canonical version', () => {
    const s = buildCommunitySnapshot({ id: 'CR-20261108-AAAAAAAAAAAAAAAA', targetType: 'domain', targetDisplay: 'x.example', category: 'scam', description: 'd'.repeat(25), submittedAt: 't', status: 'validated' });
    assert.equal(s.canonicalVersion, 'cyberlens-community/v1');
  });
});

// ---------------------------------------------------------------------------
const chainAvailable = fs.existsSync(HARDHAT);

describe('Phase 8 — registry endpoints on a real local Hardhat chain', { skip: chainAvailable ? false : 'contracts/ not installed (run npm install in contracts/)' }, () => {
  let node;
  let provider;
  let deployFresh;
  const saved = {};

  before(async () => {
    execFileSync(process.execPath, [HARDHAT, 'compile', '--quiet'], { cwd: CONTRACTS, stdio: 'ignore', env: { ...process.env, HARDHAT_DISABLE_TELEMETRY_PROMPT: 'true' } });
    node = spawn(process.execPath, [HARDHAT, 'node', '--port', String(PORT)], { cwd: CONTRACTS, stdio: 'ignore', env: { ...process.env, HARDHAT_DISABLE_TELEMETRY_PROMPT: 'true' } });
    provider = new ethers.JsonRpcProvider(RPC, ethers.Network.from(31337), { staticNetwork: ethers.Network.from(31337), cacheTimeout: -1 });
    for (let i = 0; i < 60; i++) {
      try {
        await provider.getBlockNumber();
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 250));
      }
    }
    const art = JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
    const wallet = new ethers.Wallet(DEV_KEY, provider);
    deployFresh = async () => {
      const c = await new ethers.ContractFactory(art.abi, art.bytecode, new ethers.NonceManager(new ethers.Wallet(DEV_KEY, provider))).deploy();
      await c.waitForDeployment();
      return c.getAddress();
    };
    const contract = await new ethers.ContractFactory(art.abi, art.bytecode, wallet).deploy();
    await contract.waitForDeployment();

    for (const k of ['CHAIN_MODE', 'LOCAL_RPC_URL', 'REGISTRY_CONTRACT_ADDRESS', 'REGISTRY_SIGNER_PRIVATE_KEY']) saved[k] = env[k];
    env.CHAIN_MODE = 'local';
    env.LOCAL_RPC_URL = RPC;
    env.REGISTRY_CONTRACT_ADDRESS = await contract.getAddress();
    env.REGISTRY_SIGNER_PRIVATE_KEY = DEV_KEY;
    blockchainService._reset();
  });

  after(() => {
    Object.assign(env, saved);
    blockchainService._reset();
    node?.kill();
    provider?.destroy();
  });

  test.beforeEach(async () => {
    await repository.clear();
    await _resetRateLimitsForTesting();
  });

  const register = (body) => request(app).post('/api/registry/register').send(body);
  const verify = (body) => request(app).post('/api/registry/verify').send(body);

  test('registers a completed report with a real mined receipt and stores the exact snapshot', async () => {
    const rec = await repository.createInvestigation(completedRecord());
    const res = await register({ investigationId: rec.id });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const r = res.body.registry;
    assert.equal(r.status, 'registered');
    assert.match(r.txHash, /^0x[0-9a-f]{64}$/);
    assert.ok(r.blockNumber > 0);
    assert.match(r.reportHash, /^[0-9a-f]{64}$/);
    assert.equal(r.network, 'Hardhat Local');
    assert.equal(r.explorerUrl, null, 'no explorer on a local chain');
    assert.equal(r.revision, 1);

    const receipt = await provider.getTransactionReceipt(r.txHash);
    assert.equal(receipt.status, 1);
    const snapshot = await repository.getCanonicalSnapshot(rec.id);
    assert.equal(sha256Hex(snapshot), r.reportHash, 'stored snapshot is exactly what was hashed');

    const report = (await request(app).get(`/api/investigations/${rec.id}`).expect(200)).body.report;
    assert.equal(report.registry.status, 'registered');
    assert.equal(report.registry.txHash, r.txHash);
  });

  test('register is idempotent: same receipt, no new transaction', async () => {
    const rec = await repository.createInvestigation(completedRecord());
    const first = (await register({ investigationId: rec.id })).body.registry;
    const block = await provider.getBlockNumber();
    const second = (await register({ investigationId: rec.id.toLowerCase() })).body.registry;
    assert.equal(second.txHash, first.txHash);
    assert.equal(await provider.getBlockNumber(), block, 'no new block mined');
  });

  test('concurrent register calls send a single transaction', async () => {
    const rec = await repository.createInvestigation(completedRecord());
    const block = await provider.getBlockNumber();
    const [a, b] = await Promise.all([register({ investigationId: rec.id }), register({ investigationId: rec.id })]);
    assert.equal(a.body.registry.txHash, b.body.registry.txHash);
    assert.equal(await provider.getBlockNumber(), block + 1);
  });

  test('verify by ID and by hash recompute the hash and compare with the CONTRACT', async () => {
    const rec = await repository.createInvestigation(completedRecord());
    const reg = (await register({ investigationId: rec.id })).body.registry;
    const byId = (await verify({ investigationId: rec.id })).body.result;
    assert.equal(byId.integrity, 'match');
    assert.equal(byId.computedHash, reg.reportHash);
    assert.equal(byId.onChainHash, reg.reportHash);
    assert.equal(byId.txHash, reg.txHash);
    const byHash = (await verify({ reportHash: `0x${reg.reportHash.toUpperCase()}` })).body.result;
    assert.equal(byHash.integrity, 'match');
    assert.equal(byHash.investigationId, rec.id);
  });

  test('tampering with the stored report is detected as a mismatch', async () => {
    const rec = await repository.createInvestigation(completedRecord());
    await register({ investigationId: rec.id });
    await repository.updateInvestigation(rec.id, { classification: 'low_risk' });
    const res = (await verify({ investigationId: rec.id })).body.result;
    assert.equal(res.integrity, 'mismatch');
    assert.notEqual(res.computedHash, res.onChainHash);
  });

  test('unregistered reports and unknown hashes → not_registered', async () => {
    const rec = await repository.createInvestigation(completedRecord());
    assert.equal((await verify({ investigationId: rec.id })).body.result.integrity, 'not_registered');
    assert.equal((await verify({ reportHash: 'ab'.repeat(32) })).body.result.integrity, 'not_registered');
  });

  test('processing reports cannot be registered; unknown IDs are 404; bad input is 400', async () => {
    const rec = await repository.createInvestigation(completedRecord({ status: 'processing' }));
    const busy = await register({ investigationId: rec.id });
    assert.equal(busy.status, 409);
    assert.equal(busy.body.error.code, 'CONFLICT');
    assert.equal((await register({ investigationId: 'INV-20261108-0000000000000000' })).status, 404);
    assert.equal((await register({ investigationId: 'bogus' })).status, 400);
    assert.equal((await register({})).status, 400);
    assert.equal((await verify({ reportHash: 'xyz' })).status, 400);
  });

  test('after a backend restart (registry memory lost) the chain record is recovered, not re-sent', async () => {
    const rec = await repository.createInvestigation(completedRecord());
    const first = (await register({ investigationId: rec.id })).body.registry;
    if (repository.kind === 'supabase') {
      await repository.db.from('cl_registry_entries').delete().not('investigation_id', 'is', null);
    } else {
      repository.registryEntries.clear();
      repository.registryByHash.clear();
    }
    await repository.updateInvestigation(rec.id, { registry: { status: 'not_registered' } });
    const block = await provider.getBlockNumber();
    const again = (await register({ investigationId: rec.id })).body.registry;
    assert.equal(again.status, 'registered');
    assert.equal(again.txHash, first.txHash, 'original tx found via the contract event');
    assert.equal(await provider.getBlockNumber(), block);
  });

  test('a reset chain / new contract is detected: the report is registered again, never shown stale', async () => {
    const rec = await repository.createInvestigation(completedRecord());
    const first = (await register({ investigationId: rec.id })).body.registry;
    const original = env.REGISTRY_CONTRACT_ADDRESS;
    env.REGISTRY_CONTRACT_ADDRESS = await deployFresh(); // simulates `npm run node` restart + redeploy
    blockchainService._reset();
    try {
      const again = (await register({ investigationId: rec.id })).body.registry;
      assert.equal(again.status, 'registered');
      assert.notEqual(again.txHash, first.txHash, 'a new transaction on the new contract');
      assert.equal(again.contractAddress, env.REGISTRY_CONTRACT_ADDRESS);
      assert.equal((await verify({ investigationId: rec.id })).body.result.integrity, 'match');
    } finally {
      env.REGISTRY_CONTRACT_ADDRESS = original;
      blockchainService._reset();
    }
  });

  test('threat feed lists real provider data only and never raw URLs', async () => {
    const rec = await repository.createInvestigation(completedRecord());
    await register({ investigationId: rec.id });
    const res = await request(app).get('/api/registry').expect(200);
    const item = res.body.items.find((i) => i.investigationId === rec.id);
    assert.equal(item.classification, 'confirmed_malicious');
    assert.equal(item.txStatus, 'confirmed');
    assert.deepEqual(item.providers, ['Google Safe Browsing'], 'URLhaus was unavailable, so it is not listed');
    assert.deepEqual(item.intelMatches, [{ provider: 'Google Safe Browsing', threatType: 'SOCIAL_ENGINEERING' }]);
    assert.equal(item.category, 'phishing');
    assert.ok(!res.text.includes('paypa1-login') && !res.text.includes('token'));
  });

  test('validated community reports can be anchored; others cannot', async () => {
    const id = generateCommunityId();
    await repository.createCommunityReport({ id, targetType: 'domain', target: 'evil.example', targetDisplay: 'evil.example', category: 'scam', description: 'A long enough description here.', status: 'pending_review' });
    assert.equal((await register({ communityReportId: id })).status, 409);
    await repository.updateCommunityReport(id, { status: 'validated', validatedAt: '2026-11-08T05:00:00.000Z' });
    const res = await register({ communityReportId: id });
    assert.equal(res.status, 200);
    assert.equal(res.body.registry.status, 'registered');
    assert.equal((await repository.getCommunityReport(id)).registry.status, 'registered');
    assert.equal((await verify({ investigationId: id })).body.result.integrity, 'match');
    const feed = await request(app).get('/api/registry').expect(200);
    assert.ok(!feed.body.items.some((i) => i.investigationId === id), 'community entries are not in the investigation feed');
  });

  test('health reports blockchain "ok" only after a real contract check', async () => {
    _clearHealthCache();
    const res = await request(app).get('/api/health').expect(200);
    assert.equal(res.body.services.blockchain, 'ok');
    assert.ok(!res.text.includes(RPC) && !res.text.includes(env.REGISTRY_CONTRACT_ADDRESS));
  });

  test('no chain configured or chain unreachable → 503 CHAIN_UNAVAILABLE (never a fake result)', async () => {
    const rec = await repository.createInvestigation(completedRecord());
    const addr = env.REGISTRY_CONTRACT_ADDRESS;
    env.REGISTRY_CONTRACT_ADDRESS = '';
    blockchainService._reset();
    let res = await register({ investigationId: rec.id });
    assert.equal(res.status, 503);
    assert.equal(res.body.error.code, 'CHAIN_UNAVAILABLE');
    assert.equal((await verify({ investigationId: rec.id })).status, 503);

    env.REGISTRY_CONTRACT_ADDRESS = addr;
    env.LOCAL_RPC_URL = 'http://127.0.0.1:1';
    blockchainService._reset();
    res = await verify({ investigationId: rec.id });
    assert.equal(res.status, 503);
    res = await register({ investigationId: rec.id });
    assert.equal(res.status, 503);
    const report = (await request(app).get(`/api/investigations/${rec.id}`)).body.report;
    assert.equal(report.registry.status, 'failed', 'the UI can offer a retry');
    _clearHealthCache();
    assert.equal((await request(app).get('/api/health')).body.services.blockchain, 'unavailable');

    env.LOCAL_RPC_URL = RPC;
    blockchainService._reset();
  });
});
