import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeMessage, extractIndicators, resolveOverlaps } from '../src/services/messageAnalyzer.js';
import { buildReport } from '../src/services/reportBuilder.js';
import { env } from '../src/config/env.js';

const PHISH =
  'URGENT: Your SBI account has been suspended. Click http://sbi-kyc-update.example/verify within 24 hours to avoid being permanently blocked. ' +
  'Please enter your OTP and password. You also get a cashback reward of Rs 5,000! Call +91 98765 43210 or mail help@sbi-care.example';

const offline = async () => {
  throw new Error('offline');
};

// GSB/URLhaus mock: `listed` URLs match, everything else is clean. Records request bodies.
function providerMock(listed = [], seen = []) {
  return async (url, opts = {}) => {
    seen.push(String(opts.body || ''));
    if (String(url).includes('safebrowsing')) {
      const body = JSON.parse(opts.body);
      const u = body.threatInfo.threatEntries[0].url;
      return { ok: true, status: 200, json: async () => (listed.some((l) => u.startsWith(l)) ? { matches: [{ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM' }] } : {}) };
    }
    return { ok: true, status: 200, json: async () => ({ query_status: 'no_results' }) };
  };
}

const originalKey = env.GOOGLE_SAFE_BROWSING_API_KEY;
test.afterEach(() => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = originalKey;
});

test('Phase 4: exactly 4 fixed message checks', async () => {
  const r = await analyzeMessage({ content: PHISH, fetchFn: offline });
  assert.deepEqual(r.checks.map((c) => c.id), ['indicators', 'tactics', 'threat_intel', 'links']);
});

test('Phase 4: extracts URLs, domains, emails and phones (incl. defanged links)', () => {
  const ind = extractIndicators(PHISH);
  assert.deepEqual(ind.urls, ['http://sbi-kyc-update.example/verify']);
  assert.deepEqual(ind.emails, ['help@sbi-care.example']);
  assert.deepEqual(ind.phones, ['+91 98765 43210']);
  assert.ok(ind.domains.includes('sbi-kyc-update.example'));
  const defanged = extractIndicators('Go to hxxps://evil[.]example/login now, or visit www.shop.example.');
  assert.deepEqual(defanged.urls, ['https://evil.example/login', 'http://www.shop.example/']);
  const noise = extractIndicators('See report.pdf and the file notes.txt, total 5,000 on 2026-11-08.');
  assert.deepEqual(noise.domains, []);
  assert.deepEqual(noise.phones, []);
});

test('Phase 4: highlight offsets point into the ORIGINAL text and never overlap', async () => {
  const r = await analyzeMessage({ content: PHISH, fetchFn: offline });
  const hs = r.message.highlights;
  assert.ok(hs.length >= 8);
  for (const h of hs) assert.equal(PHISH.slice(h.start, h.end), h.phrase);
  for (let i = 1; i < hs.length; i++) assert.ok(hs[i].start >= hs[i - 1].end, 'no overlaps, sorted');
  const tactics = new Set(hs.map((h) => h.tactic));
  for (const t of ['urgency', 'account_suspension', 'impersonation', 'threat', 'suspicious_link', 'otp_request', 'password_request', 'fake_reward']) {
    assert.ok(tactics.has(t), t);
  }
  assert.equal(r.message.tactics.find((t) => t.key === 'urgency').count, 2);
});

test('Phase 4: overlap resolution keeps the higher-priority / longer span', () => {
  const kept = resolveOverlaps([
    { start: 0, end: 10, tactic: 'urgency' },
    { start: 5, end: 20, tactic: 'otp_request' },
    { start: 20, end: 25, tactic: 'urgency' },
  ]);
  assert.deepEqual(kept.map((k) => k.tactic), ['otp_request', 'urgency']);
});

test('Phase 4: brand/link mismatch and risky link features become findings', async () => {
  const r = await analyzeMessage({ content: PHISH, fetchFn: offline });
  const links = r.checks.find((c) => c.id === 'links');
  assert.equal(links.status, 'completed');
  assert.ok(links.findings.some((f) => f.id.startsWith('f_link_mismatch') && f.severity === 'high'));
  const ip = await analyzeMessage({ content: 'Verify at http://203.0.113.9/login and https://bit.ly/abc', fetchFn: offline });
  const ids = ip.findings.map((f) => f.id).join(' ');
  assert.match(ids, /f_link_ip/);
  assert.match(ids, /f_link_short/);
  const legit = await analyzeMessage({ content: 'Your SBI statement is ready on https://onlinesbi.sbi/ today.', fetchFn: offline });
  assert.ok(!legit.findings.some((f) => f.id.startsWith('f_link_mismatch')), 'official brand domain is not a mismatch');
});

test('Phase 4: phishing message without a provider match → high_risk, never confirmed_malicious', async () => {
  const a = await analyzeMessage({ content: PHISH, fetchFn: offline });
  const report = await buildReport({ type: 'message', target: { display: 'Submitted message' }, checks: a.checks, message: a.message, fetchFn: offline });
  assert.equal(report.classification, 'high_risk');
  assert.equal(report.coverage.total, 4);
  assert.equal(a.checks.find((c) => c.id === 'threat_intel').status, 'unavailable', 'providers down is not clean');
  assert.equal(report.explanation.source, 'template');
  assert.ok(!report.explanation.summary.includes('unknown'));
});

test('Phase 4: link listed by Google Safe Browsing → confirmed_malicious', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'test-key';
  const a = await analyzeMessage({ content: PHISH, fetchFn: providerMock(['http://sbi-kyc-update.example']) });
  const ti = a.checks.find((c) => c.id === 'threat_intel');
  assert.equal(ti.status, 'match_found');
  assert.ok(ti.findings.every((f) => f.category === 'confirmed' && f.checkId === 'threat_intel'));
  const report = await buildReport({ type: 'message', checks: a.checks, message: a.message, fetchFn: offline });
  assert.equal(report.classification, 'confirmed_malicious');
});

test('Phase 4: ordinary message → low_risk; no links means threat_intel/links are not_checked (never "clean")', async () => {
  const content = 'Hi team, the meeting moved to 3pm tomorrow in room 4. See you there.';
  const a = await analyzeMessage({ content, fetchFn: offline });
  assert.equal(a.checks.find((c) => c.id === 'threat_intel').status, 'not_checked');
  assert.equal(a.checks.find((c) => c.id === 'links').status, 'not_checked');
  const report = await buildReport({ type: 'message', checks: a.checks, message: a.message, fetchFn: offline });
  assert.equal(report.classification, 'low_risk');
  assert.notEqual(report.confidence, 'high');
  assert.equal(report.coverage.completed, 2);
  assert.deepEqual(a.message.highlights, []);
});

test('Phase 4: only extracted URLs are sent to providers, never the message text', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'test-key';
  const seen = [];
  await analyzeMessage({ content: PHISH, fetchFn: providerMock([], seen) });
  assert.ok(seen.length >= 2);
  for (const body of seen) {
    assert.ok(!body.includes('enter your OTP'), 'no message text');
    assert.ok(!body.includes('98765'), 'no phone numbers');
  }
});

test('Phase 4: at most 5 links are looked up; the rest is reported, not hidden', async () => {
  env.GOOGLE_SAFE_BROWSING_API_KEY = 'test-key';
  const content = Array.from({ length: 7 }, (_, i) => `https://site${i}.example/x`).join(' ');
  const seen = [];
  const a = await analyzeMessage({ content, fetchFn: providerMock([], seen) });
  const ti = a.checks.find((c) => c.id === 'threat_intel');
  assert.equal(seen.length, 10); // 5 links × 2 providers
  assert.match(ti.detail, /2 more link\(s\) not checked/);
});
