import { Router } from 'express';
import { getCsrfToken, register, login, logout, getCurrentUser } from '../controllers/authController.js';
import { csrfProtection } from '../middleware/csrf.js';
import { requireAuth } from '../middleware/auth.js';
import { loginLimiter, registerLimiter, csrfTokenLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// Logout needs CSRF only when there is a signed-in session to end;
// a repeated logout (no session) just clears the cookie.
const csrfIfSignedIn = (req, res, next) => (req.session?.userId ? csrfProtection(req, res, next) : next());

router.get('/auth/csrf', csrfTokenLimiter, getCsrfToken);
router.post('/auth/register', registerLimiter, csrfProtection, register);
router.post('/auth/login', loginLimiter, csrfProtection, login);
router.post('/auth/logout', csrfIfSignedIn, logout);
router.get('/auth/me', requireAuth, getCurrentUser);

export default router;
