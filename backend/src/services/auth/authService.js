import crypto from 'node:crypto';
import { repository } from '../../store/repository.js';
import { AppError } from '../../utils/response.js';
import { ERROR_CODES } from '../../config/constants.js';
import { logger } from '../../utils/logger.js';
import { passwordHasher } from './passwordHasher.js';
import { cleanFullName, normalizeEmail, passwordProblem } from './authValidation.js';

const INVALID_CREDENTIALS = 'Incorrect email or password.';

/** Public view of a user. Never includes passwordHash or other secrets. */
export function toSafeUser(user) {
  if (!user) return null;
  return { id: user.id, fullName: user.fullName, email: user.email, role: user.role || 'user', createdAt: user.createdAt };
}

const emailTaken = () => new AppError('An account with this email already exists.', { code: ERROR_CODES.EMAIL_TAKEN, status: 409 });

/**
 * Account logic. Storage only through the shared repository
 * (createUser / getUserByEmail / getUserById / updateUser).
 */
export const authService = {
  /** Input must already be validated. New accounts are always role "user". */
  async register({ fullName, email, password }) {
    if (await repository.getUserByEmail(email)) throw emailTaken();
    const now = new Date().toISOString();
    const user = {
      id: `USR-${crypto.randomBytes(12).toString('hex')}`,
      fullName,
      email,
      passwordHash: await passwordHasher.hash(password),
      role: 'user',
      createdAt: now,
      updatedAt: now,
    };
    try {
      const created = await repository.createUser(user);
      logger.info('user_registered', { userId: created.id });
      return toSafeUser(created);
    } catch (err) {
      if (/already exists/i.test(err?.message || '')) throw emailTaken(); // race with a concurrent signup
      throw err;
    }
  },

  /** Returns the safe user, or throws a generic 401 for any mismatch. */
  async authenticate({ email, password }) {
    const user = await repository.getUserByEmail(email);
    if (!user?.passwordHash) {
      await passwordHasher.verifyDummy(password);
      throw new AppError(INVALID_CREDENTIALS, { code: ERROR_CODES.INVALID_CREDENTIALS, status: 401 });
    }
    if (!(await passwordHasher.verify(user.passwordHash, password))) {
      logger.info('login_failed', { userId: user.id });
      throw new AppError(INVALID_CREDENTIALS, { code: ERROR_CODES.INVALID_CREDENTIALS, status: 401 });
    }
    if (passwordHasher.needsRehash(user.passwordHash)) {
      try {
        await repository.updateUser(user.id, { passwordHash: await passwordHasher.hash(password) });
      } catch (err) {
        logger.warn('rehash_failed', { userId: user.id, error: err?.message });
      }
    }
    return toSafeUser(user);
  },

  async getUserById(id) {
    return toSafeUser(await repository.getUserById(id));
  },

  /**
   * Creates the admin account from ADMIN_EMAIL / ADMIN_PASSWORD at startup
   * (before the server listens, so nobody can pre-register that email).
   * Idempotent; promotes an existing account with that email to admin.
   */
  async bootstrapAdmin({ email, password, fullName }) {
    if (!email || !password) return null;
    const normalized = normalizeEmail(email);
    const problem = passwordProblem(password, normalized);
    if (problem) throw new Error(`ADMIN_PASSWORD is too weak: ${problem}`);
    const existing = await repository.getUserByEmail(normalized);
    if (existing) {
      const changes = {};
      if (existing.role !== 'admin') changes.role = 'admin';
      // With a persistent database the account survives restarts: keep its
      // password in sync with ADMIN_PASSWORD so .env stays the source of truth.
      if (!(await passwordHasher.verify(existing.passwordHash, password).catch(() => false))) {
        changes.passwordHash = await passwordHasher.hash(password);
      }
      if (Object.keys(changes).length) await repository.updateUser(existing.id, changes);
      return toSafeUser({ ...existing, ...changes });
    }
    const now = new Date().toISOString();
    const created = await repository.createUser({
      id: `USR-${crypto.randomBytes(12).toString('hex')}`,
      fullName: cleanFullName(fullName) || 'CYBERLENS Admin',
      email: normalized,
      passwordHash: await passwordHasher.hash(password),
      role: 'admin',
      createdAt: now,
      updatedAt: now,
    });
    logger.info('admin_bootstrapped', { userId: created.id });
    return toSafeUser(created);
  },
};
