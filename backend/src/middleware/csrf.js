import crypto from 'node:crypto';
import { env } from '../config/env.js';
import { AppError } from '../utils/response.js';
import { ERROR_CODES } from '../config/constants.js';

/**
 * CSRF protection for cookie-authenticated, state-changing requests.
 *
 * 1. Origin check: if the browser sends Origin (or Referer) it must be one of
 *    FRONTEND_URL's origins. Cross-site posts are rejected outright.
 * 2. Synchronizer token: `X-CSRF-Token` must equal the token in the server-
 *    side session. Get one from GET /api/auth/csrf (also returned by login,
 *    register and /me). Rotated on login/register, dropped on logout.
 */
export const CSRF_HEADER = 'x-csrf-token';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const newToken = () => crypto.randomBytes(32).toString('base64url');

export function issueCsrfToken(req) {
  if (!req.session.csrfToken) req.session.csrfToken = newToken();
  return req.session.csrfToken;
}

export function rotateCsrfToken(req) {
  req.session.csrfToken = newToken();
  return req.session.csrfToken;
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

function originOf(value) {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

const reject = (message) => new AppError(message, { code: ERROR_CODES.CSRF_INVALID, status: 403 });

export function csrfProtection(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  const allowed = env.FRONTEND_ORIGINS;
  const origin = req.get('origin');
  const source = origin && origin !== 'null' ? origin : originOf(req.get('referer') || '');
  if (origin === 'null' || (source && !allowed.includes(source))) {
    return next(reject('This request was blocked because it came from an untrusted origin.'));
  }

  const sent = req.get(CSRF_HEADER);
  const expected = req.session?.csrfToken;
  if (!expected || !sent || !safeEqual(sent, expected)) {
    return next(reject('Your security token is missing or expired. Refresh the page and try again.'));
  }
  return next();
}
