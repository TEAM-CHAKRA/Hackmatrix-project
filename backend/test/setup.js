// Loaded before every test file (see "test" script in package.json).
// Cheap Argon2 parameters keep the suite fast; real defaults are used in dev/prod.
process.env.NODE_ENV ??= 'test';
process.env.ARGON2_MEMORY_COST ??= '4096';
process.env.ARGON2_TIME_COST ??= '1';
// Tests use the in-memory repository unless TEST_DB_PROVIDER says otherwise, so
// `npm test` never touches the real Supabase project even when backend/.env has keys.
process.env.DB_PROVIDER = process.env.TEST_DB_PROVIDER || 'memory';
