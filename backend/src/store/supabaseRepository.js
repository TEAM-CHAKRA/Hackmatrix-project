import { createClient } from '@supabase/supabase-js';
export { classifySupabaseKey } from './supabaseKey.js';

/**
 * SupabaseRepository — persistent implementation of the repository contract
 * documented in ./repository.js, backed by the tables in supabase/schema.sql.
 *
 * Same method names, same arguments, same return shapes as MemoryRepository:
 *   - every method is async;
 *   - records come back as plain JSON-safe copies (ISO date strings);
 *   - not found → null;
 *   - IDs, emails and hashes are matched case-insensitively;
 *   - update methods merge top-level fields ({ ...existing, ...updates }),
 *     done atomically in Postgres by public.cl_merge_record().
 *
 * Server-side only: it needs the SECRET (service_role) key, which bypasses
 * Row Level Security. Never import this into the frontend.
 */

const T = {
  users: 'cl_users',
  sessions: 'cl_sessions',
  investigations: 'cl_investigations',
  snapshots: 'cl_canonical_snapshots',
  registry: 'cl_registry_entries',
  community: 'cl_community_reports',
};

const PG_UNIQUE_VIOLATION = '23505';

// Keep a reference to the platform fetch so code (or tests) that patch
// globalThis.fetch for outbound scanning never break database calls.
const nativeFetch = globalThis.fetch.bind(globalThis);
const DB_TIMEOUT_MS = 15000;
// Every database call gets a time limit, so a slow network can never leave the
// server hanging (e.g. while it starts up and checks the schema).
const platformFetch = (input, init = {}) =>
  nativeFetch(input, init.signal ? init : { ...init, signal: AbortSignal.timeout(DB_TIMEOUT_MS) });

function normalizeKey(key) {
  if (typeof key !== 'string') return key;
  return key.trim().toLowerCase();
}

function cloneJson(data) {
  if (data === null || data === undefined) return null;
  return JSON.parse(JSON.stringify(data));
}

function toIso(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? fallback : d.toISOString();
}

/** Error wrapper that never leaks keys or row contents. */
export class DatabaseError extends Error {
  constructor(operation, cause) {
    const code = cause?.code ? ` (${cause.code})` : '';
    super(`Database ${operation} failed${code}: ${cause?.message || 'unknown error'}`);
    this.name = 'DatabaseError';
    this.code = cause?.code;
    this.hint = cause?.hint;
  }
}

export class SupabaseRepository {
  /**
   * @param {{ url: string, key: string, client?: object, allowClear?: boolean }} opts
   */
  constructor({ url, key, client, allowClear = false } = {}) {
    if (!client && (!url || !key)) throw new Error('SupabaseRepository needs SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY');
    this.db =
      client ||
      createClient(url, key, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
        global: { headers: { 'X-Client-Info': 'cyberlens-backend' }, fetch: (...args) => platformFetch(...args) },
      });
    this.allowClear = allowClear;
    this.kind = 'supabase';
  }

  // ---------------------------------------------------------------- helpers --

  async #one(operation, query) {
    const { data, error } = await query.maybeSingle();
    if (error) throw new DatabaseError(operation, error);
    return data ? cloneJson(data.data) : null;
  }

  async #upsert(operation, table, row, onConflict) {
    const { error } = await this.db.from(table).upsert(row, { onConflict });
    if (error) throw new DatabaseError(operation, error);
  }

  async #merge(operation, table, id, patch) {
    // `{ ...existing, field: undefined }` deletes the field in the in-memory
    // repository (JSON drops undefined); mirror that with p_remove.
    const remove = Object.keys(patch || {}).filter((k) => patch[k] === undefined);
    const { data, error } = await this.db.rpc('cl_merge_record', {
      p_table: table,
      p_id: id,
      p_patch: cloneJson(patch) || {},
      p_remove: remove,
    });
    if (error) throw new DatabaseError(operation, error);
    return data ? cloneJson(data) : null;
  }

  async #list(operation, query) {
    const { data, error } = await query;
    if (error) throw new DatabaseError(operation, error);
    return (data || []).map((row) => cloneJson(row.data));
  }

  /** Cheap connectivity check used by /api/health. Resolves true/false. */
  async ping() {
    try {
      const { error } = await this.db.from(T.investigations).select('id').limit(0);
      return !error;
    } catch {
      return false;
    }
  }

  // --------------------------------------------------------- investigations --

  async createInvestigation(data) {
    if (!data?.id) throw new Error('Investigation record requires an id');
    const nowIso = new Date().toISOString();
    const record = cloneJson({ ...data, createdAt: toIso(data.createdAt, nowIso), updatedAt: nowIso });
    await this.#upsert('createInvestigation', T.investigations, {
      id: normalizeKey(data.id),
      type: record.type ?? null,
      data: record,
      created_at: record.createdAt,
      updated_at: nowIso,
    }, 'id');
    return cloneJson(record);
  }

  async getInvestigation(id) {
    if (!id) return null;
    return this.#one('getInvestigation', this.db.from(T.investigations).select('data').eq('id', normalizeKey(id)));
  }

  async updateInvestigation(id, updates) {
    if (!id) return null;
    return this.#merge('updateInvestigation', T.investigations, normalizeKey(id), {
      ...(updates || {}),
      updatedAt: new Date().toISOString(),
    });
  }

  async listInvestigations(filter = {}) {
    let q = this.db.from(T.investigations).select('data').order('created_at', { ascending: true });
    if (filter.type) q = q.eq('type', filter.type);
    return this.#list('listInvestigations', q);
  }

  async storeCanonicalSnapshot(id, snapshotString) {
    if (!id) throw new Error('Snapshot requires an id');
    await this.#upsert('storeCanonicalSnapshot', T.snapshots, {
      investigation_id: normalizeKey(id),
      snapshot: String(snapshotString),
    }, 'investigation_id');
  }

  async getCanonicalSnapshot(id) {
    if (!id) return null;
    const { data, error } = await this.db
      .from(T.snapshots)
      .select('snapshot')
      .eq('investigation_id', normalizeKey(id))
      .maybeSingle();
    if (error) throw new DatabaseError('getCanonicalSnapshot', error);
    return data ? data.snapshot : null;
  }

  // ---------------------------------------------------------------- registry --

  async createRegistryEntry(entry) {
    if (!entry?.investigationId) throw new Error('Registry entry requires an investigationId');
    const record = cloneJson({ ...entry, registeredAt: toIso(entry.registeredAt, new Date().toISOString()) });
    await this.#upsert('createRegistryEntry', T.registry, {
      investigation_id: normalizeKey(entry.investigationId),
      report_hash: entry.reportHash ? normalizeKey(entry.reportHash) : null,
      data: record,
    }, 'investigation_id');
    return cloneJson(record);
  }

  async getRegistryEntryByInvestigationId(investigationId) {
    if (!investigationId) return null;
    return this.#one(
      'getRegistryEntryByInvestigationId',
      this.db.from(T.registry).select('data').eq('investigation_id', normalizeKey(investigationId))
    );
  }

  async getRegistryEntryByHash(reportHash) {
    if (!reportHash) return null;
    // Newest wins, matching the in-memory hash index (last write wins).
    return this.#one(
      'getRegistryEntryByHash',
      this.db
        .from(T.registry)
        .select('data')
        .eq('report_hash', normalizeKey(reportHash))
        .order('inserted_at', { ascending: false })
        .limit(1)
    );
  }

  async listRegistryEntries() {
    return this.#list(
      'listRegistryEntries',
      this.db.from(T.registry).select('data').order('inserted_at', { ascending: true })
    );
  }

  async updateRegistryEntry(investigationId, updates) {
    if (!investigationId) return null;
    return this.#merge('updateRegistryEntry', T.registry, normalizeKey(investigationId), updates || {});
  }

  // --------------------------------------------------------------- community --

  async createCommunityReport(report) {
    if (!report?.id) throw new Error('Community report requires an id');
    const record = cloneJson({
      ...report,
      submittedAt: toIso(report.submittedAt, new Date().toISOString()),
      status: report.status || 'pending_review',
      validation: report.validation || { confirms: 0, disputes: 0 },
    });
    await this.#upsert('createCommunityReport', T.community, {
      id: normalizeKey(report.id),
      submitted_at: record.submittedAt,
      data: record,
    }, 'id');
    return cloneJson(record);
  }

  async getCommunityReport(id) {
    if (!id) return null;
    return this.#one('getCommunityReport', this.db.from(T.community).select('data').eq('id', normalizeKey(id)));
  }

  async listCommunityReports() {
    return this.#list(
      'listCommunityReports',
      this.db.from(T.community).select('data').order('submitted_at', { ascending: false })
    );
  }

  async voteCommunityReport(id, voteType) {
    const report = await this.getCommunityReport(id);
    if (!report) return null;
    const validation = { ...(report.validation || { confirms: 0, disputes: 0 }) };
    if (voteType === 'confirm') validation.confirms = (validation.confirms || 0) + 1;
    else if (voteType === 'dispute') validation.disputes = (validation.disputes || 0) + 1;
    return this.#merge('voteCommunityReport', T.community, normalizeKey(id), { validation });
  }

  async updateCommunityReport(id, updates) {
    if (!id) return null;
    return this.#merge('updateCommunityReport', T.community, normalizeKey(id), updates || {});
  }

  // ------------------------------------------------------------------- users --

  async createUser(user) {
    if (!user?.id || !user?.email) throw new Error('User requires an id and email');
    const email = normalizeKey(user.email);
    const record = cloneJson({ ...user, email, createdAt: toIso(user.createdAt, new Date().toISOString()) });
    const { error } = await this.db.from(T.users).insert({
      id: user.id,
      email,
      data: record,
      created_at: record.createdAt,
    });
    if (error) {
      if (error.code === PG_UNIQUE_VIOLATION) throw new Error('Email already exists');
      throw new DatabaseError('createUser', error);
    }
    return cloneJson(record);
  }

  async getUserById(id) {
    if (!id) return null;
    return this.#one('getUserById', this.db.from(T.users).select('data').eq('id', id));
  }

  async getUserByEmail(email) {
    if (!email) return null;
    return this.#one('getUserByEmail', this.db.from(T.users).select('data').eq('email', normalizeKey(email)));
  }

  async updateUser(id, updates) {
    if (!id) return null;
    const { id: _id, email: _email, ...rest } = updates || {};
    return this.#merge('updateUser', T.users, id, { ...rest, updatedAt: new Date().toISOString() });
  }

  // ---------------------------------------------------------------- sessions --

  async createSession(sessionId, sessionData) {
    const expiresAt =
      sessionData.expiresAt instanceof Date ? sessionData.expiresAt.toISOString() : sessionData.expiresAt;
    const record = cloneJson({ ...sessionData, expiresAt, createdAt: new Date().toISOString() });
    await this.#upsert('createSession', T.sessions, {
      sid: sessionId,
      user_id: sessionData.userId || null,
      data: record,
      // Sessions always need an expiry in the database; default 8 h if missing.
      expires_at: toIso(expiresAt, new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString()),
    }, 'sid');
  }

  async getSession(sessionId) {
    if (!sessionId) return null;
    const { data, error } = await this.db
      .from(T.sessions)
      .select('data, expires_at')
      .eq('sid', sessionId)
      .maybeSingle();
    if (error) throw new DatabaseError('getSession', error);
    if (!data) return null;
    if (new Date(data.expires_at).getTime() < Date.now()) {
      await this.deleteSession(sessionId);
      return null;
    }
    return cloneJson(data.data);
  }

  async deleteSession(sessionId) {
    if (!sessionId) return;
    const { error } = await this.db.from(T.sessions).delete().eq('sid', sessionId);
    if (error) throw new DatabaseError('deleteSession', error);
  }

  async pruneExpiredSessions() {
    const { data, error } = await this.db.rpc('cl_prune_expired_sessions');
    if (error) throw new DatabaseError('pruneExpiredSessions', error);
    return Number(data) || 0;
  }

  // ------------------------------------------------------------- diagnostics --

  /**
   * Wipes every CYBERLENS table. Refused unless explicitly allowed
   * (test runs against a throwaway database), so it can never empty the
   * real project by accident.
   */
  async clear() {
    if (!this.allowClear) {
      throw new Error('clear() is disabled on the Supabase repository (it would delete real data).');
    }
    const wipes = [
      [T.sessions, 'sid'],
      [T.snapshots, 'investigation_id'],
      [T.registry, 'investigation_id'],
      [T.community, 'id'],
      [T.investigations, 'id'],
      [T.users, 'id'],
    ];
    for (const [table, col] of wipes) {
      const { error } = await this.db.from(table).delete().not(col, 'is', null);
      if (error) throw new DatabaseError(`clear(${table})`, error);
    }
  }
}
