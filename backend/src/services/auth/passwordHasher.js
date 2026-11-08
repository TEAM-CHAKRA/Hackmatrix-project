import argon2 from 'argon2';
import { env } from '../../config/env.js';

/**
 * Argon2id password hashing via the `argon2` library (no hand-rolled crypto).
 * Parameters come from ARGON2_* env vars (defaults: OWASP m=19 MiB, t=2, p=1).
 * The random salt is embedded in the PHC hash string.
 */
const options = () => ({
  type: argon2.argon2id,
  memoryCost: env.ARGON2_MEMORY_COST,
  timeCost: env.ARGON2_TIME_COST,
  parallelism: env.ARGON2_PARALLELISM,
});

let dummyHash = null;

export const passwordHasher = {
  hash: (password) => argon2.hash(password, options()),

  async verify(hash, password) {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false; // malformed hash → mismatch
    }
  },

  /** True when the stored hash used different/weaker parameters. */
  needsRehash(hash) {
    try {
      return argon2.needsRehash(hash, options());
    } catch {
      return false;
    }
  },

  /** Spend the same time as a real verify when the account does not exist. */
  async verifyDummy(password) {
    dummyHash ??= await argon2.hash('cyberlens-timing-equalizer-0', options());
    await this.verify(dummyHash, password);
    return false;
  },
};
