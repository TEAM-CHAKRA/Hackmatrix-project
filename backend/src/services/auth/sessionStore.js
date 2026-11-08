import session from 'express-session';
import { repository } from '../../store/repository.js';

/**
 * RepositorySessionStore — express-session store backed by the shared
 * repository's session methods (createSession / getSession / deleteSession).
 *
 * Because sessions live behind the repository interface, they move to the
 * persistent database automatically when the repository is swapped
 * (e.g. Supabase). With the in-memory repository, sessions are lost on
 * restart and not shared between instances (see ALLOW_MEMORY_SESSION_STORE).
 */
export class RepositorySessionStore extends session.Store {
  constructor({ repo = repository, defaultTtlMs = 8 * 60 * 60 * 1000, pruneIntervalMs = 10 * 60 * 1000 } = {}) {
    super();
    this.repo = repo;
    this.defaultTtlMs = defaultTtlMs;
    this.available = true; // test hook: simulate an outage
    if (typeof repo.pruneExpiredSessions === 'function') {
      this.timer = setInterval(() => repo.pruneExpiredSessions().catch(() => {}), pruneIntervalMs);
      this.timer.unref?.();
    }
  }

  #expiry(sess) {
    const e = sess?.cookie?.expires;
    const t = e ? new Date(e).getTime() : NaN;
    return new Date(Number.isFinite(t) ? t : Date.now() + this.defaultTtlMs).toISOString();
  }

  #run(promiseFn, cb) {
    if (!this.available) return cb?.(new Error('Session store unavailable'));
    promiseFn().then((v) => cb?.(null, v), (err) => cb?.(err));
  }

  get(sid, cb) {
    this.#run(async () => {
      const rec = await this.repo.getSession(sid);
      if (!rec?.data) return null;
      return JSON.parse(rec.data);
    }, cb);
  }

  set(sid, sess, cb) {
    this.#run(
      () =>
        this.repo.createSession(sid, {
          userId: sess.userId || null,
          data: JSON.stringify(sess),
          expiresAt: this.#expiry(sess),
        }),
      cb
    );
  }

  touch(sid, sess, cb) {
    this.set(sid, sess, cb);
  }

  destroy(sid, cb) {
    this.#run(() => this.repo.deleteSession(sid), cb);
  }

  close() {
    clearInterval(this.timer);
  }

  /** Readiness probe: write, read back and delete a throwaway session. */
  async probe() {
    if (!this.available) return false;
    const sid = `__probe__${process.hrtime.bigint()}`;
    await this.repo.createSession(sid, {
      userId: null,
      data: JSON.stringify({ probe: true }),
      expiresAt: new Date(Date.now() + 5000).toISOString(),
    });
    const back = await this.repo.getSession(sid);
    await this.repo.deleteSession(sid);
    return back?.data === JSON.stringify({ probe: true });
  }
}

export const sessionStore = new RepositorySessionStore();
