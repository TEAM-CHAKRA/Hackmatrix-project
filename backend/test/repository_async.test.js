import test from 'node:test';
import assert from 'node:assert/strict';
import { repository, MemoryRepository } from '../src/store/repository.js';
import { createInvestigation, getInvestigation } from '../src/controllers/investigationController.js';
import { errorHandler } from '../src/middleware/errorHandler.js';
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

test.beforeEach(async () => {
  await repository.clear();
});

test('Repository: all methods are async and return promises', async () => {
  const repo = new MemoryRepository();

  const createPromise = repo.createInvestigation({ id: 'INV-TEST-1', type: 'url' });
  assert.ok(createPromise instanceof Promise, 'createInvestigation must return a Promise');
  const created = await createPromise;
  assert.equal(created.id, 'INV-TEST-1');

  const getPromise = repo.getInvestigation('INV-TEST-1');
  assert.ok(getPromise instanceof Promise, 'getInvestigation must return a Promise');
  const fetched = await getPromise;
  assert.equal(fetched.id, 'INV-TEST-1');

  const updatePromise = repo.updateInvestigation('INV-TEST-1', { status: 'completed' });
  assert.ok(updatePromise instanceof Promise, 'updateInvestigation must return a Promise');
  const updated = await updatePromise;
  assert.equal(updated.status, 'completed');

  const listPromise = repo.listInvestigations();
  assert.ok(listPromise instanceof Promise, 'listInvestigations must return a Promise');
  const list = await listPromise;
  assert.equal(list.length, 1);

  const snapshotPromise = repo.storeCanonicalSnapshot('INV-TEST-1', '{"snapshot":"exact"}');
  assert.ok(snapshotPromise instanceof Promise, 'storeCanonicalSnapshot must return a Promise');
  await snapshotPromise;

  const getSnapshotPromise = repo.getCanonicalSnapshot('INV-TEST-1');
  assert.ok(getSnapshotPromise instanceof Promise, 'getCanonicalSnapshot must return a Promise');
  assert.equal(await getSnapshotPromise, '{"snapshot":"exact"}');

  const notFound = await repo.getInvestigation('NON_EXISTENT');
  assert.equal(notFound, null, 'Non-existent record lookup must return null');
});

test('Repository: returns plain JSON-safe data copies without references to stored objects', async () => {
  const repo = new MemoryRepository();

  const originalInput = {
    id: 'INV-20261108-MUTATION0001',
    type: 'url',
    tags: new Set(['phishing', 'typosquat']),
    metadata: { rating: 5 },
    createdAt: new Date('2026-11-08T00:00:00.000Z'),
  };

  const stored = await repo.createInvestigation(originalInput);

  // Assert stored has plain string dates and no Set / class instances
  assert.equal(typeof stored.createdAt, 'string');
  assert.equal(stored.createdAt, '2026-11-08T00:00:00.000Z');
  assert.ok(!(stored.tags instanceof Set), 'Set instances must be converted to plain JSON-safe data');

  // Mutate the returned record
  stored.metadata.rating = 999;
  stored.type = 'message';

  // Fetch a fresh record and verify internal store was NOT mutated
  const fresh = await repo.getInvestigation('INV-20261108-MUTATION0001');
  assert.equal(fresh.metadata.rating, 5, 'Internal store must not be mutated by modifying returned records');
  assert.equal(fresh.type, 'url', 'Internal store must not be mutated by modifying returned records');
});

test('Repository: canonical snapshots are stored and returned as the exact string', async () => {
  const repo = new MemoryRepository();
  const rawJsonString = '{\n  "canonical": "version 1.0",\n  "hash": "0xABCDEF1234567890"\n}';

  await repo.storeCanonicalSnapshot('INV-SNAP-1', rawJsonString);
  const retrieved = await repo.getCanonicalSnapshot('INV-SNAP-1');

  assert.strictEqual(retrieved, rawJsonString, 'Canonical snapshot must match the exact string byte-for-byte');
});

test('Requirement 4: Normalize investigation and community IDs on lookup case-insensitively', async () => {
  // 1. Investigation ID case-insensitivity
  const invUpper = 'INV-20261108-ABC123DEF4567890';
  const invLower = 'inv-20261108-abc123def4567890';
  const invMixed = 'Inv-20261108-Abc123Def4567890';

  await repository.createInvestigation({
    id: invUpper,
    type: 'url',
    status: 'completed',
    target: { display: 'https://example.com' },
  });

  // Look up using lower, mixed, and upper case
  const resLower = await repository.getInvestigation(invLower);
  const resMixed = await repository.getInvestigation(invMixed);
  const resUpper = await repository.getInvestigation(invUpper);

  assert.ok(resLower, 'Lookup with lowercase ID must find the investigation');
  assert.ok(resMixed, 'Lookup with mixed-case ID must find the investigation');
  assert.ok(resUpper, 'Lookup with uppercase ID must find the investigation');
  assert.equal(resLower.id, invUpper);
  assert.equal(resMixed.id, invUpper);

  // Also verify canonical snapshot case-insensitivity
  await repository.storeCanonicalSnapshot(invUpper, '{"snap":"case_test"}');
  assert.equal(await repository.getCanonicalSnapshot(invLower), '{"snap":"case_test"}');

  // 2. Community Report ID case-insensitivity
  const repUpper = 'CR-20261108-AABBCCDDEEFF0011';
  const repLower = 'cr-20261108-aabbccddeeff0011';

  await repository.createCommunityReport({
    id: repUpper,
    targetType: 'domain',
    target: 'phishing.example',
    category: 'phishing',
    description: 'Suspicious domain reported in phishing email campaign.',
  });

  const repFromLower = await repository.getCommunityReport(repLower);
  assert.ok(repFromLower, 'Lookup with lowercase ID must find community report');
  assert.equal(repFromLower.id, repUpper);

  // Voting on lowercase ID must update the record
  const voted = await repository.voteCommunityReport(repLower, 'confirm');
  assert.equal(voted.validation.confirms, 1);
  const checkVoted = await repository.getCommunityReport(repUpper);
  assert.equal(checkVoted.validation.confirms, 1);
});

test('Requirement 5: async-ready test double with delayed methods resolves correctly in investigation flow', async () => {
  // Wrap repository methods in a delayed test double
  const delayMs = 25;
  const originalCreate = repository.createInvestigation;
  const originalGet = repository.getInvestigation;

  let delayInvoked = 0;

  repository.createInvestigation = async function (...args) {
    delayInvoked++;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    return originalCreate.apply(this, args);
  };

  repository.getInvestigation = async function (...args) {
    delayInvoked++;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    return originalGet.apply(this, args);
  };

  try {
    // 1. Run investigation POST flow
    const postReq = {
      body: {
        type: 'message',
        content: 'Urgent: Suspicious security alert for your account. Click here to confirm.',
      },
    };
    const postRes = createMockRes();

    await createInvestigation(postReq, postRes, (err) => {
      if (err) throw err;
    });

    assert.equal(postRes.statusCode, 202);
    assert.equal(postRes.body.success, true);
    assert.equal(postRes.body.status, 'processing');
    const createdId = postRes.body.investigationId;
    assert.ok(createdId);

    // 2. Run investigation GET flow
    const getReq = { params: { id: createdId } };
    const getRes = createMockRes();

    await getInvestigation(getReq, getRes, (err) => {
      if (err) throw err;
    });

    assert.equal(getRes.statusCode, 200);
    assert.equal(getRes.body.success, true);
    assert.equal(getRes.body.report.id, createdId);
    assert.equal(getRes.body.report.type, 'message');
    assert.ok(delayInvoked >= 2, 'Delayed async methods must be invoked and awaited');
  } finally {
    // Restore original methods
    repository.createInvestigation = originalCreate;
    repository.getInvestigation = originalGet;
  }
});

test('Async error handling: repository failure in Express route handler passes to error middleware and returns standard error envelope', async () => {
  const originalGet = repository.getInvestigation;

  // Simulate database connection failure in repository
  repository.getInvestigation = async function () {
    throw new Error('Database connection failed: Supabase unreachable');
  };

  try {
    const req = {
      method: 'GET',
      originalUrl: '/api/investigations/INV-FAIL-1',
      params: { id: 'INV-FAIL-1' },
    };
    const res = createMockRes();

    let passedToNext = null;
    await getInvestigation(req, res, (err) => {
      passedToNext = err;
    });

    assert.ok(passedToNext, 'Route handler must catch rejected promise and pass to next()');
    assert.equal(passedToNext.message, 'Database connection failed: Supabase unreachable');

    // Feed to global errorHandler middleware
    errorHandler(passedToNext, req, res, () => { });

    assert.equal(res.statusCode, 500);
    assert.equal(res.body.success, false);
    assert.equal(res.body.error.code, ERROR_CODES.INTERNAL);
    assert.equal(res.body.error.message, 'An internal server error occurred while processing your request.');
  } finally {
    repository.getInvestigation = originalGet;
  }
});
