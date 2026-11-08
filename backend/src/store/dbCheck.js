/**
 * Database self-check: confirms the Supabase project has everything the
 * backend needs (tables + functions) and that the key works. Used at server
 * start-up and by `npm run db:check`. Never prints keys or row contents.
 */

export const REQUIRED_TABLES = [
  'cl_users',
  'cl_sessions',
  'cl_investigations',
  'cl_canonical_snapshots',
  'cl_registry_entries',
  'cl_community_reports',
];

/** Turn a Supabase/PostgREST error into one plain sentence a teammate can act on. */
export function explainDbError(error) {
  const code = error?.code || '';
  const msg = `${error?.message || ''} ${error?.details || ''}`;
  if (code === 'PGRST205' || code === '42P01' || /does not exist|Could not find the table/i.test(msg)) {
    return 'missing — run backend/supabase/schema.sql in the Supabase SQL Editor';
  }
  if (code === 'PGRST202' || /Could not find the function/i.test(msg)) {
    return 'function missing — run backend/supabase/schema.sql in the Supabase SQL Editor';
  }
  if (code === '42501' || /permission denied/i.test(msg)) {
    return 'permission denied — SUPABASE_SERVICE_ROLE_KEY must be the secret (service_role) key, not the anon key';
  }
  if (/Invalid API key|invalid.*jwt|JWSError|JWT|No API key|unauthori[sz]ed/i.test(msg) || /^PGRST30/.test(code) || error?.status === 401) {
    return 'key rejected — copy the secret (service_role) key again from Supabase → Project Settings → API Keys';
  }
  if (/fetch failed|ENOTFOUND|ECONNREFUSED|EAI_AGAIN|network/i.test(msg)) {
    return 'cannot reach Supabase — check SUPABASE_URL and your internet connection';
  }
  return `error${code ? ` ${code}` : ''}: ${error?.message || 'unknown'}`;
}

/**
 * @param {import('./supabaseRepository.js').SupabaseRepository} repo
 * @returns {Promise<{ ok: boolean, checks: Array<{ name: string, ok: boolean, detail: string }> }>}
 */
export async function checkSupabaseSchema(repo) {
  const checks = [];
  for (const table of REQUIRED_TABLES) {
    try {
      // A real GET (not HEAD) so errors come back with a readable body.
      const { error } = await repo.db.from(table).select('*').limit(0);
      checks.push({ name: `table ${table}`, ok: !error, detail: error ? explainDbError(error) : 'ok' });
    } catch (err) {
      checks.push({ name: `table ${table}`, ok: false, detail: explainDbError(err) });
    }
  }
  for (const fn of ['cl_prune_expired_sessions']) {
    try {
      const { error } = await repo.db.rpc(fn);
      checks.push({ name: `function ${fn}`, ok: !error, detail: error ? explainDbError(error) : 'ok' });
    } catch (err) {
      checks.push({ name: `function ${fn}`, ok: false, detail: explainDbError(err) });
    }
  }
  try {
    // A merge on an id that cannot exist: proves the function exists and runs, changes nothing.
    const { error } = await repo.db.rpc('cl_merge_record', {
      p_table: 'cl_investigations',
      p_id: '__cyberlens_db_check__',
      p_patch: {},
      p_remove: [],
    });
    checks.push({ name: 'function cl_merge_record', ok: !error, detail: error ? explainDbError(error) : 'ok' });
  } catch (err) {
    checks.push({ name: 'function cl_merge_record', ok: false, detail: explainDbError(err) });
  }
  return { ok: checks.every((c) => c.ok), checks };
}

/**
 * After a restart, scans that were still running can never finish (the job
 * queue lives in memory). Mark them failed honestly instead of leaving the
 * website polling forever. Returns how many were updated.
 */
export async function failInterruptedInvestigations(repo) {
  const all = await repo.listInvestigations();
  let n = 0;
  for (const inv of all) {
    if (inv.status !== 'processing' && inv.status !== 'queued') continue;
    const steps = Array.isArray(inv.steps)
      ? inv.steps.map((s) =>
          s.status === 'running' ? { ...s, status: 'failed' } : s.status === 'pending' ? { ...s, status: 'skipped' } : s
        )
      : inv.steps;
    await repo.updateInvestigation(inv.id, {
      status: 'failed',
      error: { message: 'The server restarted before this scan finished. Please run the scan again.' },
      steps,
      completedAt: new Date().toISOString(),
    });
    n++;
  }
  return n;
}
