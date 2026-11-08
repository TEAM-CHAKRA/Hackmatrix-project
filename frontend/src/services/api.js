// CYBERLENS API client. All calls go to the backend; secrets never live here.
// When VITE_USE_MOCKS=true, calls are served by clearly-labelled demo fixtures.

import * as mock from './mock/mockApi.js';

const BASE = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
// Demo fixtures: `npm run dev:demo` (mode=demo) or VITE_USE_MOCKS=true.
export const USE_MOCKS = import.meta.env.MODE === 'demo' || import.meta.env.VITE_USE_MOCKS === 'true';

export class ApiError extends Error {
  constructor(message, { status = 0, code = 'UNKNOWN', details } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

// CSRF: the backend requires an X-CSRF-Token header on state-changing requests
// made with the session cookie. The token is kept in memory only (never in
// localStorage) and refreshed from GET /auth/csrf when missing or rejected.
const SAFE_METHODS = new Set(['GET', 'HEAD']);
let csrfToken = null;

// ---- Waking a sleeping backend ------------------------------------------------
// Free hosting (e.g. Render) stops the backend after ~15 idle minutes; the first
// request then takes up to a minute while it starts, and the hosting proxy may
// answer 502/503/504 meanwhile. Before talking to a backend we haven't heard from
// recently, ping /health/live until it answers, so real requests (especially
// POSTs) are only sent once it is awake and are never sent twice.
const WAKE_STATUSES = new Set([502, 503, 504]);
const AWAKE_FOR_MS = 10 * 60 * 1000;
const WAKE_LIMIT_MS = 120 * 1000;
let lastAwakeAt = 0;
let wakingPromise = null;
const wakeListeners = new Set();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Subscribe to "backend is waking up" changes; returns an unsubscribe function. */
export function onBackendWaking(listener) {
  wakeListeners.add(listener);
  return () => wakeListeners.delete(listener);
}

function wakeBackend() {
  if (wakingPromise) return wakingPromise;
  wakingPromise = (async () => {
    const until = Date.now() + WAKE_LIMIT_MS;
    let announced = false;
    while (Date.now() < until) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 30000);
      try {
        const res = await fetch(`${BASE}/health/live`, { cache: 'no-store', credentials: 'include', signal: controller.signal });
        if (res.ok) {
          lastAwakeAt = Date.now();
          return true;
        }
      } catch {
        /* still starting */
      } finally {
        clearTimeout(timer);
      }
      if (!announced) {
        announced = true;
        wakeListeners.forEach((fn) => fn(true));
      }
      await sleep(3000);
    }
    return false;
  })().finally(() => {
    wakeListeners.forEach((fn) => fn(false));
    wakingPromise = null;
  });
  return wakingPromise;
}

async function fetchCsrfToken() {
  try {
    const res = await request('/auth/csrf', { timeoutMs: 6000, csrf: false });
    csrfToken = res?.csrfToken || null;
  } catch {
    csrfToken = null; // best effort: endpoints that don't need it still work
  }
  return csrfToken;
}

async function request(path, { method = 'GET', body, timeoutMs = 20000, csrf = true, retried = false, wakeRetried = false } = {}) {
  if (Date.now() - lastAwakeAt > AWAKE_FOR_MS) await wakeBackend();
  const needsCsrf = csrf && !SAFE_METHODS.has(method);
  if (needsCsrf && !csrfToken) await fetchCsrfToken();
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (needsCsrf && csrfToken) headers['X-CSRF-Token'] = csrfToken;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      // Session is an httpOnly cookie set by the backend; never stored in JS.
      credentials: 'include',
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      throw new ApiError('The request timed out. The backend may be busy or unreachable.', { code: 'TIMEOUT' });
    }
    throw new ApiError('Cannot reach the CYBERLENS server. Reload the page; if it keeps happening, make sure the backend and frontend are running.', { code: 'NETWORK' });
  }
  clearTimeout(timer);

  // Hosting proxy says the backend is asleep or restarting.
  if (WAKE_STATUSES.has(res.status) && !(res.headers.get('content-type') || '').includes('application/json')) {
    lastAwakeAt = 0;
    const awake = await wakeBackend();
    // Safe to repeat only reads; a write may or may not have reached the server.
    if (awake && SAFE_METHODS.has(method) && !wakeRetried) {
      return request(path, { method, body, timeoutMs, csrf, retried, wakeRetried: true });
    }
    throw new ApiError(
      awake
        ? 'The server was waking up. Please try again now.'
        : 'The CYBERLENS server is starting up. Free hosting sleeps when idle, so this can take a minute. Please try again shortly.',
      { status: res.status, code: 'BACKEND_WAKING' }
    );
  }
  lastAwakeAt = Date.now();

  let data = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      throw new ApiError(`Unexpected response from server (HTTP ${res.status}).`, { status: res.status, code: 'BAD_RESPONSE' });
    }
  }

  if (typeof data?.csrfToken === 'string') csrfToken = data.csrfToken;

  // Contract: { success: false, error: { code, message, details? } }
  if (!res.ok || data?.success === false) {
    const e = data?.error || {};
    // Token missing/expired (e.g. after the server restarted): refresh once and retry.
    if (res.status === 403 && e.code === 'CSRF_INVALID' && needsCsrf && !retried) {
      csrfToken = null;
      return request(path, { method, body, timeoutMs, csrf, retried: true });
    }
    throw new ApiError(e.message || `Request failed (HTTP ${res.status}).`, {
      status: res.status,
      code: e.code || 'HTTP_ERROR',
      details: e.details,
    });
  }
  return data;
}

// ---- Investigations ---------------------------------------------------------

/** @returns {Promise<{investigationId: string, status: string}>} */
export function createInvestigation(payload) {
  if (USE_MOCKS) return mock.createInvestigation(payload);
  return request('/investigations', { method: 'POST', body: payload });
}

/** @returns {Promise<{report: object}>} */
export function getInvestigation(id) {
  if (USE_MOCKS) return mock.getInvestigation(id);
  return request(`/investigations/${encodeURIComponent(id)}`);
}

// ---- Registry ---------------------------------------------------------------

export function registerReport(investigationId) {
  if (USE_MOCKS) return mock.registerReport(investigationId);
  return request('/registry/register', { method: 'POST', body: { investigationId }, timeoutMs: 90000 });
}

/** query: { investigationId } or { reportHash } */
export function verifyReport(query) {
  if (USE_MOCKS) return mock.verifyReport(query);
  return request('/registry/verify', { method: 'POST', body: query, timeoutMs: 45000 });
}

export function listRegistry() {
  if (USE_MOCKS) return mock.listRegistry();
  return request('/registry');
}

// ---- Health -----------------------------------------------------------------

export function getHealth() {
  if (USE_MOCKS) return mock.getHealth();
  return request('/health', { timeoutMs: 6000 });
}

// ---- Community reports -----------------------------------------------------

export function listCommunityReports() {
  if (USE_MOCKS) return mock.listCommunityReports();
  return request('/community/reports');
}

/** report: { targetType, target, category, description } */
export function submitCommunityReport(report) {
  if (USE_MOCKS) return mock.submitCommunityReport(report);
  return request('/community/reports', { method: 'POST', body: report });
}

/** One vote per voter; voting again with the other type switches the vote. */
export function voteCommunityReport(id, voteType) {
  if (USE_MOCKS) return mock.voteCommunityReport();
  return request(`/community/reports/${encodeURIComponent(id)}/vote`, { method: 'POST', body: { voteType } });
}

/** Admin only: pending_review | under_review | validated | disputed | rejected */
export function updateCommunityReportStatus(id, status) {
  if (USE_MOCKS) return mock.updateCommunityReportStatus();
  return request(`/community/reports/${encodeURIComponent(id)}/status`, { method: 'PATCH', body: { status } });
}

/** Anchor a VALIDATED community report on-chain. */
export function registerCommunityReport(communityReportId) {
  if (USE_MOCKS) return mock.registerCommunityReport();
  return request('/registry/register', { method: 'POST', body: { communityReportId }, timeoutMs: 90000 });
}

// ---- Authentication --------------------------------------------------------
// Passwords are sent once over HTTPS to the backend, which hashes them.
// The frontend never stores passwords or tokens; the session is an httpOnly cookie.

export function login({ email, password }) {
  if (USE_MOCKS) return mock.login();
  return request('/auth/login', { method: 'POST', body: { email, password } });
}

export function register({ fullName, email, password, acceptTerms }) {
  if (USE_MOCKS) return mock.register();
  return request('/auth/register', { method: 'POST', body: { fullName, email, password, acceptTerms } });
}

export function logout() {
  if (USE_MOCKS) return Promise.resolve({ success: true });
  return request('/auth/logout', { method: 'POST' }).finally(() => {
    csrfToken = null; // the session (and its token) is gone
  });
}

export function getCurrentUser() {
  if (USE_MOCKS) return mock.getCurrentUser();
  return request('/auth/me', { timeoutMs: 6000 });
}
