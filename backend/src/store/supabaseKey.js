/** Dependency-free helper shared by config/env.js and the Supabase repository. */

/**
 * Inspect a Supabase key without printing it. Returns
 * 'secret' | 'publishable' | 'unknown'.
 */
export function classifySupabaseKey(key) {
  if (typeof key !== 'string' || !key) return 'unknown';
  if (key.startsWith('sb_secret_')) return 'secret';
  if (key.startsWith('sb_publishable_')) return 'publishable';
  const parts = key.split('.');
  if (parts.length === 3) {
    try {
      const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
      if (payload.role === 'service_role') return 'secret';
      if (payload.role === 'anon' || payload.role === 'authenticated') return 'publishable';
    } catch {
      /* fall through */
    }
  }
  return 'unknown';
}
