// In-browser mock of the CYBERLENS backend, for UI development only.
// - Investigation progress is simulated over a few seconds (labelled as demo).
// - Blockchain registration and verification are NOT simulated: they return an
//   explicit "unavailable in demo mode" error, so no fake tx hash ever appears.

import { DEFAULT_STEPS } from '../../utils/constants.js';
import { pickFixture } from './fixtures.js';

const store = new Map();
const STEP_MS = 900;

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function mockError(message, code = 'DEMO_MODE') {
  const err = new Error(message);
  err.name = 'ApiError';
  err.code = code;
  err.status = 503;
  return err;
}

function makeId() {
  const rand = crypto.getRandomValues(new Uint8Array(4));
  return `DEMO-${Array.from(rand, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase()}`;
}

export async function createInvestigation(payload) {
  await delay(250);
  const id = makeId();
  store.set(id, { payload, createdAt: new Date().toISOString(), startedMs: Date.now(), fixture: pickFixture(payload) });
  return { success: true, investigationId: id, status: 'processing' };
}

export async function getInvestigation(id) {
  await delay(150);
  const entry = store.get(id);
  if (!entry) {
    throw mockError(
      'Investigation not found. Demo reports exist only in this browser tab — they disappear on reload.',
      'NOT_FOUND'
    );
  }
  const { fixture, payload, createdAt, startedMs } = entry;
  const steps = DEFAULT_STEPS[fixture.type].map((s) => ({ ...s }));
  const elapsed = Date.now() - startedMs;
  const stepIndex = Math.floor(elapsed / STEP_MS);
  const done = stepIndex >= steps.length;

  steps.forEach((s, i) => {
    if (fixture.type === 'message' && s.key === 'tls_security') {
      s.status = i < stepIndex ? 'skipped' : 'pending';
      s.detail = 'Not applicable to message investigations';
      return;
    }
    s.status = i < stepIndex ? 'completed' : i === stepIndex ? 'running' : 'pending';
  });

  const base = {
    id,
    demo: true,
    createdAt,
    type: fixture.type,
    target: fixture.target,
    steps,
  };

  if (!done) return { success: true, report: { ...base, status: 'processing' } };

  return {
    success: true,
    report: {
      ...fixture,
      ...base,
      status: 'completed',
      completedAt: new Date(startedMs + STEP_MS * steps.length).toISOString(),
      // Submitted message text is only kept in this tab's memory for highlighting.
      message: fixture.message ? { ...fixture.message, text: payload.content?.trim() } : undefined,
    },
  };
}

export async function registerReport() {
  await delay(400);
  throw mockError(
    'On-chain registration is unavailable in demo mode. Connect the backend and testnet wallet to create a real transaction.'
  );
}

export async function verifyReport() {
  await delay(400);
  throw mockError('Integrity verification needs the backend and blockchain connection. It is unavailable in demo mode.');
}

export async function listRegistry() {
  await delay(300);
  return { success: true, demo: true, items: [] };
}

export async function getHealth() {
  return {
    success: true,
    demo: true,
    status: 'demo',
    services: {
      database: 'not_connected',
      googleSafeBrowsing: 'not_connected',
      urlhaus: 'not_connected',
      crtsh: 'not_connected',
      ai: 'not_connected',
      blockchain: 'not_connected',
    },
  };
}

// ---- Community & auth: NOT simulated -------------------------------------------
// Demo mode never pretends a submission, login or account creation succeeded.

export async function listCommunityReports() {
  await delay(250);
  return { success: true, demo: true, items: [] };
}

export async function submitCommunityReport() {
  await delay(400);
  throw mockError('Community report submission needs the backend. Nothing was submitted in demo mode.');
}

export async function voteCommunityReport() {
  await delay(250);
  throw mockError('Voting needs the backend. No vote was recorded in demo mode.');
}

export async function updateCommunityReportStatus() {
  await delay(250);
  throw mockError('Moderation needs the backend. Nothing was changed in demo mode.');
}

export async function registerCommunityReport() {
  await delay(250);
  throw mockError('On-chain registration needs the backend. Nothing was registered in demo mode.');
}

export async function login() {
  await delay(400);
  throw mockError('Login needs the CYBERLENS backend. Demo mode cannot sign you in.');
}

export async function register() {
  await delay(400);
  throw mockError('Account creation needs the CYBERLENS backend. No account was created in demo mode.');
}

export async function getCurrentUser() {
  const err = mockError('Not signed in (demo mode).', 'UNAUTHENTICATED');
  err.status = 401;
  throw err;
}
