import session from 'express-session';
import { env } from '../config/env.js';
import { sessionStore } from '../services/auth/sessionStore.js';

/**
 * Server-side sessions with a hardened httpOnly cookie.
 * - Session data lives in the repository (RepositorySessionStore), never in
 *   the cookie; the cookie holds only a signed random ID.
 * - saveUninitialized:false: anonymous visitors get no session until
 *   something is stored (a CSRF token or a login).
 * - rolling:true: expiry slides with activity (SESSION_MAX_AGE idle seconds).
 */
export const sessionMiddleware = session({
  name: env.SESSION_COOKIE_NAME,
  secret: env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  unset: 'destroy',
  proxy: Boolean(env.TRUST_PROXY),
  cookie: {
    httpOnly: true,
    secure: env.SESSION_COOKIE_SECURE,
    sameSite: env.SESSION_COOKIE_SAME_SITE,
    maxAge: env.SESSION_MAX_AGE * 1000,
    domain: env.SESSION_COOKIE_DOMAIN || undefined,
    path: '/',
  },
});

/** Options for clearing the session cookie (must match how it was set). */
export function clearCookieOptions() {
  return {
    httpOnly: true,
    secure: env.SESSION_COOKIE_SECURE,
    sameSite: env.SESSION_COOKIE_SAME_SITE,
    domain: env.SESSION_COOKIE_DOMAIN || undefined,
    path: '/',
  };
}
