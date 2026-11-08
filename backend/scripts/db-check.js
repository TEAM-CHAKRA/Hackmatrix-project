#!/usr/bin/env node
/**
 * npm run db:check — is Supabase connected and ready for CYBERLENS?
 *
 * 1. Reads backend/.env (SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY).
 * 2. Checks every table and function from supabase/schema.sql exists.
 * 3. Writes, reads back and deletes a temporary record and session.
 * Prints plain-English results. Never prints keys or real user data.
 */
import crypto from 'node:crypto';
import { env } from '../src/config/env.js';
import { createRepository } from '../src/store/repository.js';
import { checkSupabaseSchema, explainDbError } from '../src/store/dbCheck.js';

const ok = (m) => console.log(`  \x1b[32m✔\x1b[0m ${m}`);
const bad = (m) => console.log(`  \x1b[31m✖\x1b[0m ${m}`);

async function main() {
  console.log('\nCYBERLENS database check\n');
  if (env.DB_PROVIDER !== 'supabase') {
    bad('Supabase is not configured. Add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to backend/.env (see docs/DATABASE.md).');
    process.exit(1);
  }
  ok(`Project URL set (${new URL(env.SUPABASE_URL).host})`);
  ok('Secret key set (value hidden)');

  const repo = createRepository(env);
  const { ok: schemaOk, checks } = await checkSupabaseSchema(repo);
  for (const c of checks) (c.ok ? ok : bad)(`${c.name}: ${c.detail}`);
  if (!schemaOk) {
    console.log('\nNot ready. Fix the ✖ lines above, then run `npm run db:check` again.\n');
    process.exit(1);
  }

  // Round trip with throwaway records (removed again below).
  const id = `INV-DBCHECK-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
  const sid = `__dbcheck__${crypto.randomBytes(6).toString('hex')}`;
  try {
    await repo.createInvestigation({ id, type: 'url', status: 'processing', note: 'db-check' });
    const merged = await repo.updateInvestigation(id.toLowerCase(), { status: 'completed' });
    const back = await repo.getInvestigation(id);
    if (back?.status !== 'completed' || merged?.note !== 'db-check') throw new Error('read-back did not match');
    ok('Write → update → read back works');

    await repo.createSession(sid, { userId: null, data: '{"check":true}', expiresAt: new Date(Date.now() + 60000).toISOString() });
    const s = await repo.getSession(sid);
    if (s?.data !== '{"check":true}') throw new Error('session read-back did not match');
    ok('Sessions (login) storage works');
  } catch (err) {
    bad(`Round trip failed: ${err.code ? explainDbError(err) : err.message}`);
    process.exitCode = 1;
  } finally {
    await repo.db.from('cl_investigations').delete().eq('id', id.toLowerCase());
    await repo.deleteSession(sid).catch(() => {});
  }
  if (process.exitCode) return;
  ok('Temporary test records removed');
  console.log('\n\x1b[32mSupabase is connected and ready.\x1b[0m Start the backend with `npm run dev` (or bash start-cyberlens.sh).\n');
}

main().catch((err) => {
  bad(explainDbError(err));
  process.exit(1);
});
