/**
 * REPOSITORY INTERFACE CONTRACT (src/store/repository.js)
 * 
 * This module defines the asynchronous repository interface for CYBERLENS.
 * All methods are asynchronous and return Promises.
 * Returned records are plain, JSON-safe data copies (no Map, Set, Date objects,
 * or class instances; all timestamps are ISO 8601 strings).
 * If a requested record is not found, methods return `null`.
 * Canonical snapshots are stored and returned as the exact snapshot string.
 *
 * Interface Methods:
 *
 * 1. Investigations
 *    - createInvestigation(data: object): Promise<object>
 *      Inputs: investigation object with at least `id` (e.g. INV-YYYYMMDD-...) and `type` ('url' | 'message')
 *      Output: created investigation record copy (plain JSON-safe)
 *
 *    - getInvestigation(id: string): Promise<object | null>
 *      Inputs: investigation ID string (normalized case-insensitively)
 *      Output: investigation record copy if found, otherwise `null`
 *
 *    - updateInvestigation(id: string, updates: object): Promise<object | null>
 *      Inputs: investigation ID string (normalized case-insensitively), partial updates object
 *      Output: updated investigation record copy if found, otherwise `null`
 *
 *    - listInvestigations(filter?: { type?: string }): Promise<Array<object>>
 *      Inputs: optional filter object (e.g. { type: 'url' })
 *      Output: array of investigation record copies matching filter (or all)
 *
 *    - storeCanonicalSnapshot(id: string, snapshotString: string): Promise<void>
 *      Inputs: investigation ID string (normalized case-insensitively), exact canonical JSON string
 *      Output: resolves void. Stored as the exact string without parsing or alteration.
 *
 *    - getCanonicalSnapshot(id: string): Promise<string | null>
 *      Inputs: investigation ID string (normalized case-insensitively)
 *      Output: exact canonical JSON string if found, otherwise `null`
 *
 * 2. Registry (Threat Feed & Blockchain Bridge)
 *    - createRegistryEntry(entry: object): Promise<object>
 *      Inputs: registry entry object with at least `investigationId`
 *      Output: created registry record copy (plain JSON-safe)
 *
 *    - getRegistryEntryByInvestigationId(investigationId: string): Promise<object | null>
 *      Inputs: investigation ID string (normalized case-insensitively)
 *      Output: registry entry record copy if found, otherwise `null`
 *
 *    - getRegistryEntryByHash(reportHash: string): Promise<object | null>
 *      Inputs: report sha256 hash string (normalized case-insensitively)
 *      Output: registry entry record copy if found, otherwise `null`
 *
 *    - listRegistryEntries(): Promise<Array<object>>
 *      Inputs: none
 *      Output: array of registry entry record copies
 *
 *    - updateRegistryEntry(investigationId: string, updates: object): Promise<object | null>
 *      Inputs: investigation ID string (normalized case-insensitively), partial updates object
 *      Output: updated registry entry record copy if found, otherwise `null`
 *
 * 3. Community Reports
 *    - createCommunityReport(report: object): Promise<object>
 *      Inputs: community report object with at least `id` (e.g. CR-YYYYMMDD-...)
 *      Output: created community report copy (plain JSON-safe)
 *
 *    - getCommunityReport(id: string): Promise<object | null>
 *      Inputs: report ID string (normalized case-insensitively)
 *      Output: community report copy if found, otherwise `null`
 *
 *    - listCommunityReports(): Promise<Array<object>>
 *      Inputs: none
 *      Output: array of community report copies sorted descending by submittedAt
 *
 *    - voteCommunityReport(id: string, voteType: 'confirm' | 'dispute'): Promise<object | null>
 *      Inputs: report ID string (normalized case-insensitively), voteType
 *      Output: updated community report copy if found, otherwise `null`
 *
 *    - updateCommunityReport(id: string, updates: object): Promise<object | null>
 *      Inputs: report ID string (normalized case-insensitively), partial updates object
 *      Output: updated community report copy if found, otherwise `null`
 *
 * 4. Users & Authentication
 *    - createUser(user: object): Promise<object>
 *      Inputs: user object with `id`, `email`, `passwordHash`, `fullName`
 *      Output: created user record copy (plain JSON-safe; email normalized)
 *
 *    - getUserById(id: string): Promise<object | null>
 *      Inputs: user ID string
 *      Output: user record copy if found, otherwise `null`
 *
 *    - getUserByEmail(email: string): Promise<object | null>
 *      Inputs: user email string (normalized case-insensitively)
 *      Output: user record copy if found, otherwise `null`
 *
 *    - createSession(sessionId: string, sessionData: object): Promise<void>
 *      Inputs: session ID string, sessionData with `userId` and `expiresAt`
 *      Output: resolves void
 *
 *    - getSession(sessionId: string): Promise<object | null>
 *      Inputs: session ID string
 *      Output: session record copy if active/unexpired, otherwise `null`
 *
 *    - deleteSession(sessionId: string): Promise<void>
 *      Inputs: session ID string
 *      Output: resolves void
 *
 *    - updateUser(id: string, updates: object): Promise<object | null>   [Phase 1]
 *      Inputs: user ID, partial updates (id/email are ignored)
 *      Output: updated user copy, or null
 *
 *    - pruneExpiredSessions(): Promise<number>                           [Phase 1]
 *      Removes expired sessions; resolves the number removed
 *
 * 5. Diagnostics
 *    - clear(): Promise<void>
 *      Inputs: none
 *      Output: clears all in-memory maps, resolves void
 */

import { env } from '../config/env.js';
import { SupabaseRepository } from './supabaseRepository.js';

function normalizeKey(key) {
  if (typeof key !== 'string') return key;
  return key.trim().toLowerCase();
}

function cloneJson(data) {
  if (data === null || data === undefined) return null;
  return JSON.parse(JSON.stringify(data));
}

export class MemoryRepository {
  constructor() {
    this.investigations = new Map();         // normalized id -> investigation record
    this.canonicalSnapshots = new Map();     // normalized id -> exact canonical snapshot string
    this.registryEntries = new Map();        // normalized investigationId -> registry record
    this.registryByHash = new Map();         // normalized reportHash -> normalized investigationId
    this.communityReports = new Map();       // normalized id -> community report
    this.users = new Map();                  // id -> user
    this.usersByEmail = new Map();           // normalized email -> user
    this.sessions = new Map();               // sessionId -> { userId, expiresAt }
    this.kind = 'memory';
  }

  /** Connectivity check used by /api/health (always reachable in memory). */
  async ping() {
    return true;
  }

  // =========================================================================
  // Investigations
  // =========================================================================

  async createInvestigation(data) {
    if (!data.id) throw new Error('Investigation record requires an id');
    const normId = normalizeKey(data.id);
    const nowIso = new Date().toISOString();
    const record = cloneJson({
      ...data,
      createdAt: data.createdAt ? new Date(data.createdAt).toISOString() : nowIso,
      updatedAt: nowIso,
    });
    this.investigations.set(normId, record);
    return cloneJson(record);
  }

  async getInvestigation(id) {
    if (!id) return null;
    const record = this.investigations.get(normalizeKey(id));
    return record ? cloneJson(record) : null;
  }

  async updateInvestigation(id, updates) {
    if (!id) return null;
    const normId = normalizeKey(id);
    const existing = this.investigations.get(normId);
    if (!existing) return null;

    const updated = cloneJson({
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString(),
    });
    this.investigations.set(normId, updated);
    return cloneJson(updated);
  }

  async listInvestigations(filter = {}) {
    const list = Array.from(this.investigations.values());
    if (filter.type) {
      return cloneJson(list.filter((item) => item.type === filter.type));
    }
    return cloneJson(list);
  }

  async storeCanonicalSnapshot(id, snapshotString) {
    if (!id) throw new Error('Snapshot requires an id');
    this.canonicalSnapshots.set(normalizeKey(id), String(snapshotString));
  }

  async getCanonicalSnapshot(id) {
    if (!id) return null;
    const snapshot = this.canonicalSnapshots.get(normalizeKey(id));
    return snapshot !== undefined ? snapshot : null;
  }

  // =========================================================================
  // Registry (On-chain tracking & Threat Feed)
  // =========================================================================

  async createRegistryEntry(entry) {
    if (!entry.investigationId) throw new Error('Registry entry requires an investigationId');
    const normInvId = normalizeKey(entry.investigationId);
    const record = cloneJson({
      ...entry,
      registeredAt: entry.registeredAt ? new Date(entry.registeredAt).toISOString() : new Date().toISOString(),
    });
    this.registryEntries.set(normInvId, record);
    if (entry.reportHash) {
      this.registryByHash.set(normalizeKey(entry.reportHash), normInvId);
    }
    return cloneJson(record);
  }

  async getRegistryEntryByInvestigationId(investigationId) {
    if (!investigationId) return null;
    const entry = this.registryEntries.get(normalizeKey(investigationId));
    return entry ? cloneJson(entry) : null;
  }

  async getRegistryEntryByHash(reportHash) {
    if (!reportHash) return null;
    const normHash = normalizeKey(reportHash);
    const id = this.registryByHash.get(normHash);
    if (!id) return null;
    return this.getRegistryEntryByInvestigationId(id);
  }

  async listRegistryEntries() {
    return cloneJson(Array.from(this.registryEntries.values()));
  }

  async updateRegistryEntry(investigationId, updates) {
    if (!investigationId) return null;
    const normInvId = normalizeKey(investigationId);
    const existing = this.registryEntries.get(normInvId);
    if (!existing) return null;

    const updated = cloneJson({
      ...existing,
      ...updates,
    });
    this.registryEntries.set(normInvId, updated);
    if (updated.reportHash) {
      this.registryByHash.set(normalizeKey(updated.reportHash), normInvId);
    }
    return cloneJson(updated);
  }

  // =========================================================================
  // Community Reports
  // =========================================================================

  async createCommunityReport(report) {
    if (!report.id) throw new Error('Community report requires an id');
    const normId = normalizeKey(report.id);
    const record = cloneJson({
      ...report,
      submittedAt: report.submittedAt ? new Date(report.submittedAt).toISOString() : new Date().toISOString(),
      status: report.status || 'pending_review',
      validation: report.validation || { confirms: 0, disputes: 0 },
    });
    this.communityReports.set(normId, record);
    return cloneJson(record);
  }

  async getCommunityReport(id) {
    if (!id) return null;
    const report = this.communityReports.get(normalizeKey(id));
    return report ? cloneJson(report) : null;
  }

  async listCommunityReports() {
    const list = Array.from(this.communityReports.values())
      .sort((a, b) => new Date(b.submittedAt).getTime() - new Date(a.submittedAt).getTime());
    return cloneJson(list);
  }

  async voteCommunityReport(id, voteType) {
    if (!id) return null;
    const normId = normalizeKey(id);
    const report = this.communityReports.get(normId);
    if (!report) return null;

    const validation = { ...(report.validation || { confirms: 0, disputes: 0 }) };
    if (voteType === 'confirm') {
      validation.confirms = (validation.confirms || 0) + 1;
    } else if (voteType === 'dispute') {
      validation.disputes = (validation.disputes || 0) + 1;
    }

    const updated = cloneJson({
      ...report,
      validation,
    });
    this.communityReports.set(normId, updated);
    return cloneJson(updated);
  }

  async updateCommunityReport(id, updates) {
    if (!id) return null;
    const normId = normalizeKey(id);
    const report = this.communityReports.get(normId);
    if (!report) return null;

    const updated = cloneJson({
      ...report,
      ...updates,
    });
    this.communityReports.set(normId, updated);
    return cloneJson(updated);
  }

  // =========================================================================
  // Users & Authentication
  // =========================================================================

  async createUser(user) {
    if (!user.id || !user.email) throw new Error('User requires an id and email');
    const normalizedEmail = normalizeKey(user.email);
    if (this.usersByEmail.has(normalizedEmail)) {
      throw new Error('Email already exists');
    }

    const record = cloneJson({
      ...user,
      email: normalizedEmail,
      createdAt: user.createdAt ? new Date(user.createdAt).toISOString() : new Date().toISOString(),
    });
    this.users.set(user.id, record);
    this.usersByEmail.set(normalizedEmail, record);
    return cloneJson(record);
  }

  async getUserById(id) {
    if (!id) return null;
    const user = this.users.get(id);
    return user ? cloneJson(user) : null;
  }

  async getUserByEmail(email) {
    if (!email) return null;
    const user = this.usersByEmail.get(normalizeKey(email));
    return user ? cloneJson(user) : null;
  }

  /**
   * Update a user (added for Phase 1: password-hash upgrades, role changes).
   * `id` and `email` cannot be changed. Returns the updated copy or null.
   */
  async updateUser(id, updates) {
    if (!id) return null;
    const existing = this.users.get(id);
    if (!existing) return null;
    const { id: _id, email: _email, ...rest } = updates || {};
    const updated = cloneJson({ ...existing, ...rest, updatedAt: new Date().toISOString() });
    this.users.set(id, updated);
    this.usersByEmail.set(existing.email, updated);
    return cloneJson(updated);
  }

  async createSession(sessionId, sessionData) {
    const expiresAt = sessionData.expiresAt instanceof Date
      ? sessionData.expiresAt.toISOString()
      : sessionData.expiresAt;

    this.sessions.set(sessionId, cloneJson({
      ...sessionData,
      expiresAt,
      createdAt: new Date().toISOString(),
    }));
  }

  async getSession(sessionId) {
    if (!sessionId) return null;
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    if (session.expiresAt && new Date(session.expiresAt).getTime() < Date.now()) {
      this.sessions.delete(sessionId);
      return null;
    }
    return cloneJson(session);
  }

  async deleteSession(sessionId) {
    if (sessionId) {
      this.sessions.delete(sessionId);
    }
  }

  /** Remove expired sessions (added for Phase 1; called periodically). Returns count removed. */
  async pruneExpiredSessions() {
    const now = Date.now();
    let removed = 0;
    for (const [sid, session] of this.sessions) {
      if (session.expiresAt && new Date(session.expiresAt).getTime() < now) {
        this.sessions.delete(sid);
        removed++;
      }
    }
    return removed;
  }

  // =========================================================================
  // Diagnostics / Testing Reset
  // =========================================================================

  async clear() {
    this.investigations.clear();
    this.canonicalSnapshots.clear();
    this.registryEntries.clear();
    this.registryByHash.clear();
    this.communityReports.clear();
    this.users.clear();
    this.usersByEmail.clear();
    this.sessions.clear();
  }
}

/**
 * Build the repository selected by DB_PROVIDER (see config/env.js):
 *   memory   → MemoryRepository (default; data resets on restart)
 *   supabase → SupabaseRepository (persistent; tables from supabase/schema.sql)
 */
export function createRepository(config = env) {
  if (config.DB_PROVIDER === 'supabase') {
    return new SupabaseRepository({
      url: config.SUPABASE_URL,
      key: config.SUPABASE_KEY,
      // Wiping tables is only possible in a test run that explicitly opts in
      // (a throwaway database), never against the real project.
      allowClear: config.NODE_ENV === 'test' && process.env.CYBERLENS_ALLOW_DB_WIPE === 'yes',
    });
  }
  return new MemoryRepository();
}

// Singleton repository instance shared across the entire backend process
export const repository = createRepository();
