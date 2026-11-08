import rateLimit from 'express-rate-limit';
import { ERROR_CODES } from '../config/constants.js';
import { env } from '../config/env.js';

const allLimiters = [];

function createCustomLimiter({ windowMs, max, message, skipSuccessfulRequests = false }) {
  const limiter = rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests,
    handler: (req, res) => {
      res.setHeader('Retry-After', Math.ceil(windowMs / 1000));
      res.status(429).json({
        success: false,
        error: {
          code: ERROR_CODES.RATE_LIMITED,
          message: message || 'Too many requests. Please slow down and try again later.',
          details: { retryAfterSeconds: Math.ceil(windowMs / 1000) },
        },
      });
    },
  });
  allLimiters.push(limiter);
  return limiter;
}

/** Test helper: forget all counters for a client key (e.g. '::ffff:127.0.0.1'). */
export async function _resetRateLimitsForTesting(keys = ['::ffff:127.0.0.1', '127.0.0.1', '::1']) {
  for (const l of allLimiters) for (const k of keys) await l.resetKey(k);
}

/** POST /api/investigations — 30 requests per 10 minutes per IP */
export const investigationLimiter = createCustomLimiter({
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: 'Investigation rate limit exceeded. Please wait a few minutes before submitting new targets.',
});

/** POST /api/auth/login — failed attempts per window per IP (default 5 per 15 min) */
export const loginLimiter = createCustomLimiter({
  windowMs: env.AUTH_RATE_LIMIT_WINDOW * 1000,
  max: env.AUTH_LOGIN_MAX_ATTEMPTS,
  skipSuccessfulRequests: true,
  message: 'Too many sign-in attempts. Please wait a few minutes and try again.',
});

/** POST /api/auth/register — default 5 per 15 min per IP */
export const registerLimiter = createCustomLimiter({
  windowMs: env.AUTH_RATE_LIMIT_WINDOW * 1000,
  max: env.AUTH_REGISTER_MAX_ATTEMPTS,
  message: 'Too many sign-up attempts. Please wait a few minutes and try again.',
});

/** GET /api/auth/csrf — creates an anonymous session, so cap it. */
export const csrfTokenLimiter = createCustomLimiter({
  windowMs: 15 * 60 * 1000,
  max: 300,
  message: 'Too many requests. Please slow down.',
});

/** POST /api/community/reports — 10 submissions per 15 minutes per IP */
export const communityLimiter = createCustomLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Community report submission limit reached. Please wait before submitting more reports.',
});

/** POST /api/community/reports/:id/vote — 60 votes per 15 minutes per IP */
export const communityVoteLimiter = createCustomLimiter({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: 'Too many votes. Please wait a few minutes.',
});

/** POST /api/registry/register — on-chain writes cost gas: 10 per hour per IP */
export const registryLimiter = createCustomLimiter({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: 'Registration limit reached. Please wait before registering more reports.',
});

/** POST /api/registry/verify — read-only chain calls: 60 per 10 minutes per IP */
export const verifyLimiter = createCustomLimiter({
  windowMs: 10 * 60 * 1000,
  max: 60,
  message: 'Too many verification requests. Please slow down.',
});
