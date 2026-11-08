import crypto from 'node:crypto';
import dotenv from 'dotenv';
import { z } from 'zod';
import { classifySupabaseKey } from '../store/supabaseKey.js';

dotenv.config();

/**
 * Environment configuration (validated with Zod).
 *
 * - Development/test get safe defaults so `npm run dev` works with no .env.
 * - Production FAILS FAST when essential security settings are missing or
 *   unsafe (session secret, origins, secure cookies, memory session store).
 * - Error output names variables, never their values.
 *
 * `env` is a plain mutable object so tests can toggle provider keys.
 */

const DEV_DEFAULT_SECRET = 'dev-cyberlens-session-secret-change-in-production-123456';

const bool = (fallback) =>
  z
    .union([z.boolean(), z.string()])
    .optional()
    .transform((v, ctx) => {
      if (v === undefined || v === '') return fallback;
      if (typeof v === 'boolean') return v;
      if (/^(true|1|yes)$/i.test(v)) return true;
      if (/^(false|0|no)$/i.test(v)) return false;
      ctx.addIssue({ code: 'custom', message: 'must be true or false' });
      return z.NEVER;
    });

const int = (fallback, min, max) =>
  z
    .union([z.number(), z.string()])
    .optional()
    .transform((v, ctx) => {
      if (v === undefined || v === '') return fallback;
      const n = Number(v);
      if (!Number.isInteger(n) || n < min || n > max) {
        ctx.addIssue({ code: 'custom', message: `must be an integer between ${min} and ${max}` });
        return z.NEVER;
      }
      return n;
    });

const envSchema = z.object({
  PORT: int(4000, 1, 65535),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  // Comma-separated list of exact frontend origins (CORS + CSRF origin check).
  FRONTEND_URL: z.string().default(''),
  TRUST_PROXY: z.string().optional().default(''),
  JSON_BODY_LIMIT: z.string().optional().default('100kb'),

  // --- Sessions (Phase 1) ---------------------------------------------------
  SESSION_SECRET: z.string().optional().default(''),
  SESSION_COOKIE_NAME: z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/).optional().default('cyberlens.sid'),
  SESSION_MAX_AGE: int(8 * 60 * 60, 60, 30 * 24 * 60 * 60), // seconds, sliding
  SESSION_COOKIE_SECURE: z.string().optional().default(''),
  SESSION_COOKIE_SAME_SITE: z.enum(['lax', 'strict', 'none']).optional().default('lax'),
  SESSION_COOKIE_DOMAIN: z.string().optional().default(''),
  ALLOW_MEMORY_SESSION_STORE: z.string().optional().default(''),

  // --- Password hashing (Argon2id) -------------------------------------------
  ARGON2_MEMORY_COST: int(19456, 4096, 1048576),
  ARGON2_TIME_COST: int(2, 1, 10),
  ARGON2_PARALLELISM: int(1, 1, 16),

  // --- Auth rate limits ---------------------------------------------------------
  AUTH_RATE_LIMIT_WINDOW: int(15 * 60, 1, 24 * 60 * 60), // seconds
  AUTH_LOGIN_MAX_ATTEMPTS: int(5, 1, 10000), // failed attempts per window per IP
  AUTH_REGISTER_MAX_ATTEMPTS: int(5, 1, 10000),

  // --- Optional admin bootstrap (created at startup; in-memory store) ---------
  ADMIN_EMAIL: z.string().optional().default(''),
  ADMIN_PASSWORD: z.string().optional().default(''),
  ADMIN_NAME: z.string().optional().default('CYBERLENS Admin'),

  // --- External APIs (optional; services degrade gracefully) -------------------
  GOOGLE_SAFE_BROWSING_API_KEY: z.string().optional().default(''),
  URLHAUS_API_KEY: z.string().optional().default(''),
  CERTSPOTTER_API_KEY: z.string().optional().default(''),
  GEMINI_API_KEY: z.string().optional().default(''),
  GEMINI_MODEL: z.string().optional().default('gemini-3.5-flash-lite'),

  // --- Database (Supabase) -------------------------------------------------------
  // '' = automatic: Supabase when SUPABASE_URL and a secret key are set, else memory.
  DB_PROVIDER: z.enum(['', 'memory', 'supabase']).optional().default(''),
  SUPABASE_URL: z.string().optional().default(''),
  SUPABASE_SERVICE_ROLE_KEY: z.string().optional().default(''),
  SUPABASE_SECRET_KEY: z.string().optional().default(''), // alias (new "sb_secret_…" keys)

  // --- Blockchain (Phase 8) ----------------------------------------------------
  CHAIN_MODE: z.enum(['local', 'sepolia']).optional().default('local'),
  LOCAL_RPC_URL: z.string().optional().default('http://127.0.0.1:8545'),
  SEPOLIA_RPC_URL: z.string().optional().default(''),
  REGISTRY_CONTRACT_ADDRESS: z.string().optional().default(''),
  REGISTRY_SIGNER_PRIVATE_KEY: z.string().optional().default(''),
  CHAIN_TX_TIMEOUT_MS: int(75000, 5000, 600000),
});

export class EnvError extends Error {
  constructor(problems) {
    super(`Invalid configuration:\n  - ${problems.join('\n  - ')}`);
    this.name = 'EnvError';
    this.problems = problems;
  }
}

/**
 * Parse and validate an environment object. Pure: throws EnvError.
 * @param {Record<string, string|undefined>} source
 */
export function loadEnv(source = process.env) {
  const parsed = envSchema.safeParse(source);
  const problems = [];
  if (!parsed.success) {
    for (const issue of parsed.error.issues) problems.push(`${issue.path.join('.') || 'env'}: ${issue.message}`);
    throw new EnvError(problems);
  }
  const e = { ...parsed.data };
  const isProd = e.NODE_ENV === 'production';

  // Origins
  const fallbackOrigin = isProd ? '' : 'http://localhost:5173';
  e.FRONTEND_ORIGINS = (e.FRONTEND_URL || fallbackOrigin)
    .split(',')
    .map((o) => o.trim().replace(/\/$/, ''))
    .filter(Boolean);
  if (!e.FRONTEND_URL) e.FRONTEND_URL = e.FRONTEND_ORIGINS[0] || '';
  if (e.FRONTEND_ORIGINS.length === 0) problems.push('FRONTEND_URL is required in production (comma-separated allowed origins).');
  for (const o of e.FRONTEND_ORIGINS) {
    if (o === '*') problems.push('FRONTEND_URL must list explicit origins; "*" is not allowed with credentials.');
    else if (!/^https?:\/\/[^/\s]+$/.test(o)) problems.push('FRONTEND_URL contains an invalid origin (expected e.g. https://app.example.com).');
  }

  // Session secret
  e.SESSION_SECRET_EPHEMERAL = false;
  if (!e.SESSION_SECRET) {
    if (isProd) problems.push('SESSION_SECRET is required in production.');
    else {
      e.SESSION_SECRET = crypto.randomBytes(48).toString('hex');
      e.SESSION_SECRET_EPHEMERAL = true;
    }
  } else if (e.SESSION_SECRET.length < 32) {
    problems.push('SESSION_SECRET must be at least 32 characters.');
  } else if (isProd && e.SESSION_SECRET === DEV_DEFAULT_SECRET) {
    problems.push('SESSION_SECRET is still the published development default; generate a new one.');
  }

  // Cookies
  const secureRaw = e.SESSION_COOKIE_SECURE;
  e.SESSION_COOKIE_SECURE = secureRaw === '' ? isProd : /^(true|1|yes)$/i.test(secureRaw);
  if (secureRaw !== '' && !/^(true|false|1|0|yes|no)$/i.test(secureRaw)) problems.push('SESSION_COOKIE_SECURE must be true or false.');
  if (e.SESSION_COOKIE_SAME_SITE === 'none' && !e.SESSION_COOKIE_SECURE) problems.push('SESSION_COOKIE_SAME_SITE=none requires SESSION_COOKIE_SECURE=true.');
  if (isProd && !e.SESSION_COOKIE_SECURE) problems.push('SESSION_COOKIE_SECURE must be true in production.');

  // Database provider
  e.SUPABASE_URL = e.SUPABASE_URL.trim().replace(/\/+$/, '').replace(/\/rest\/v1$/, '');
  e.SUPABASE_KEY = (e.SUPABASE_SERVICE_ROLE_KEY || e.SUPABASE_SECRET_KEY).trim();
  if (!e.DB_PROVIDER) e.DB_PROVIDER = e.SUPABASE_URL && e.SUPABASE_KEY ? 'supabase' : 'memory';
  if (e.DB_PROVIDER === 'supabase') {
    if (!e.SUPABASE_URL) problems.push('SUPABASE_URL is required when DB_PROVIDER=supabase (Supabase → Project Settings → API → Project URL).');
    else if (!/^https:\/\/[^/\s]+$/.test(e.SUPABASE_URL) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(e.SUPABASE_URL)) {
      problems.push('SUPABASE_URL must look like https://<project-ref>.supabase.co');
    }
    if (!e.SUPABASE_KEY) problems.push('SUPABASE_SERVICE_ROLE_KEY is required when DB_PROVIDER=supabase (the secret / service_role key).');
    else if (classifySupabaseKey(e.SUPABASE_KEY) === 'publishable') {
      problems.push(
        'SUPABASE_SERVICE_ROLE_KEY holds the public anon/publishable key. The backend needs the secret (service_role) key; ' +
          'the anon key cannot read the locked-down tables.'
      );
    }
  }

  const allowMem = e.ALLOW_MEMORY_SESSION_STORE;
  e.ALLOW_MEMORY_SESSION_STORE = allowMem === '' ? !isProd : /^(true|1|yes)$/i.test(allowMem);
  if (isProd && e.DB_PROVIDER === 'memory' && !e.ALLOW_MEMORY_SESSION_STORE) {
    problems.push(
      'Sessions are stored in the in-memory repository (lost on restart, not shared between instances). ' +
        'Set ALLOW_MEMORY_SESSION_STORE=true to accept this for a single-instance deployment.'
    );
  }

  // Admin bootstrap: both or neither
  if (Boolean(e.ADMIN_EMAIL) !== Boolean(e.ADMIN_PASSWORD)) problems.push('ADMIN_EMAIL and ADMIN_PASSWORD must be set together.');

  // Trust proxy: '', 'true'/'false', hop count, or subnet list
  const tp = e.TRUST_PROXY;
  e.TRUST_PROXY = tp === '' ? false : /^(true|false)$/i.test(tp) ? /^true$/i.test(tp) : Number.isInteger(Number(tp)) ? Number(tp) : tp;

  if (problems.length) throw new EnvError(problems);
  return e;
}

function loadOrExit() {
  try {
    return loadEnv(process.env);
  } catch (err) {
    if (err instanceof EnvError) {
      // Names only; values are never printed.
      console.error(`❌ ${err.message}\nSee backend/.env.example and backend/docs/SETUP.md.`);
      process.exit(1);
    }
    throw err;
  }
}

export const env = loadOrExit();
