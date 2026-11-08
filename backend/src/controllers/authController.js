import { sendSuccess } from '../utils/response.js';
import { env } from '../config/env.js';
import { authService } from '../services/auth/authService.js';
import { validateLogin, validateRegistration } from '../services/auth/authValidation.js';
import { issueCsrfToken, rotateCsrfToken } from '../middleware/csrf.js';
import { clearCookieOptions } from '../middleware/session.js';

/**
 * Phase 1 — Authentication controller.
 * Sessions: express-session (httpOnly cookie, data in the repository).
 * Passwords: Argon2id. CSRF: synchronizer token (see middleware/csrf.js).
 */

const regenerate = (req) => new Promise((resolve, reject) => req.session.regenerate((e) => (e ? reject(e) : resolve())));
const save = (req) => new Promise((resolve, reject) => req.session.save((e) => (e ? reject(e) : resolve())));
const destroy = (req) => new Promise((resolve) => req.session.destroy(() => resolve()));

/** New session ID on every sign-in (defeats session fixation); rotates CSRF. */
async function signIn(req, user) {
  await regenerate(req);
  req.session.userId = user.id;
  req.session.authAt = Date.now();
  const csrfToken = rotateCsrfToken(req);
  await save(req);
  return csrfToken;
}

/** GET /api/auth/csrf */
export function getCsrfToken(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  return sendSuccess(res, { csrfToken: issueCsrfToken(req) });
}

/** POST /api/auth/register — creates the account and signs the user in. */
export async function register(req, res, next) {
  try {
    const input = validateRegistration(req.body);
    const user = await authService.register(input);
    const csrfToken = await signIn(req, user);
    res.setHeader('Cache-Control', 'no-store');
    return sendSuccess(res, { user, csrfToken }, 201);
  } catch (err) {
    next(err);
  }
}

/** POST /api/auth/login */
export async function login(req, res, next) {
  try {
    const input = validateLogin(req.body);
    const user = await authService.authenticate(input);
    const csrfToken = await signIn(req, user);
    res.setHeader('Cache-Control', 'no-store');
    return sendSuccess(res, { user, csrfToken });
  } catch (err) {
    next(err);
  }
}

/** POST /api/auth/logout — idempotent. */
export async function logout(req, res, next) {
  try {
    await destroy(req);
    res.clearCookie(env.SESSION_COOKIE_NAME, clearCookieOptions());
    return sendSuccess(res, { message: 'Signed out.' });
  } catch (err) {
    next(err);
  }
}

/** GET /api/auth/me — mounted behind requireAuth. */
export function getCurrentUser(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  return sendSuccess(res, { user: req.auth.user, csrfToken: issueCsrfToken(req) });
}
