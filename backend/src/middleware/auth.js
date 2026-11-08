import { AppError } from '../utils/response.js';
import { ERROR_CODES } from '../config/constants.js';
import { authService } from '../services/auth/authService.js';
import { logger } from '../utils/logger.js';

/**
 * Reusable auth middleware (Phase 1). Use per route, never globally:
 *
 *   router.get('/mine', requireAuth, handler)              // signed-in users
 *   router.patch('/x', requireRole('admin'), handler)      // role-gated
 *   router.post('/y', loadAuth, handler)                   // optional user
 *
 * On success `req.auth = { userId, role, user }` (safe profile, no hash).
 * Scanner, report, registry-read and health routes stay public.
 */
async function resolve(req) {
  if (req.auth !== undefined) return req.auth;
  const userId = req.session?.userId;
  if (!userId) return (req.auth = null);
  const user = await authService.getUserById(userId);
  if (!user) {
    // Session points at a user that no longer exists: end it.
    logger.warn('session_user_missing', { userId });
    await new Promise((r) => req.session.destroy(() => r()));
    return (req.auth = null);
  }
  return (req.auth = { userId: user.id, role: user.role, user });
}

const notSignedIn = () => new AppError('Please sign in to continue.', { code: ERROR_CODES.NOT_AUTHENTICATED, status: 401 });

export function loadAuth(req, res, next) {
  resolve(req).then(() => next(), next);
}

export function requireAuth(req, res, next) {
  resolve(req).then((auth) => next(auth ? undefined : notSignedIn()), next);
}

export function requireRole(...roles) {
  return (req, res, next) =>
    resolve(req).then((auth) => {
      if (!auth) return next(notSignedIn());
      if (!roles.includes(auth.role)) {
        return next(new AppError('You do not have permission to do this.', { code: ERROR_CODES.FORBIDDEN, status: 403 }));
      }
      return next();
    }, next);
}
