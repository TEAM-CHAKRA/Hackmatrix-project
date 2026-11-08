# Backend merge handover

**Base:** the teammate backend covering Phases 0, 2, 3, 5 and 6 (`hackmatrix_cyberlens_tillp6`). It is now `backend/`. Its structure, repository, SSRF shield, URL checks, scoring and queue are unchanged except for the small fixes listed below.

**Added on top:**
- Phase 1: authentication and health.
- Phase 4: message analysis.
- Phase 7: community reports.
- Phase 8: contracts, hashing and the registry.
- Phase 9: tests and documentation.

**Test status:**
- `backend`: **179/179** passing on both the in-memory and the Supabase repository (`npm test`). This includes all 107 original tests, 18 tests against a real local Hardhat chain and a 9-test HTTP integration matrix.
- `contracts`: **12/12** passing.

## New files

| File | Purpose |
|---|---|
| `src/services/auth/passwordHasher.js` | Argon2id hashing (OWASP parameters), timing equaliser |
| `src/services/auth/sessionStore.js` | express-session store **backed by the repository's session methods** |
| `src/services/auth/authService.js` | register / authenticate / admin bootstrap |
| `src/services/auth/authValidation.js` | strict auth input validation (mass-assignment proof) |
| `src/middleware/session.js` | hardened session cookie |
| `src/middleware/csrf.js` | CSRF token and origin check |
| `src/middleware/auth.js` | `requireAuth`, `requireRole`, `loadAuth` |
| `src/services/messageAnalyzer.js` | Phase 4: the four message checks and highlights |
| `src/services/canonicalHasher.js` | Phase 8: canonical snapshot and SHA-256 |
| `src/services/blockchainService.js` | Phase 8: ethers v6 bridge (local or Sepolia), nonce-safe writes |
| `../contracts/` | Hardhat project: `CyberlensRegistry.sol`, tests, deploy script (offline solc-js compiler) |
| `test/setup.js` | fast Argon2 parameters for tests |
| `test/phase1_auth.test.js` | 21 tests |
| `test/phase4_message.test.js` | 10 tests |
| `test/phase7_community.test.js` | 7 tests |
| `test/phase8_registry.test.js` | 18 tests |
| `test/phase9_integration.test.js` | 9 tests (HTTP integration matrix) |
| `docs/SETUP.md`, `docs/API.md`, `docs/HANDOVER.md` | documentation |

## Changed files (and why)

| File | Change |
|---|---|
| `config/env.js` | Exposes `loadEnv()`. Adds session, Argon2, rate-limit, admin and chain variables. **Production fails fast** on an unsafe or missing secret, origins or cookie settings. `FRONTEND_URL` accepts a comma-separated list. |
| `config/constants.js` | New error codes. `threat_intel` (the message-flow wrapper around GSB and URLhaus) is added to `CONFIRMED_MALICIOUS_CHECK_IDS`. |
| `store/repository.js` | **Additive only:** `updateUser()` and `pruneExpiredSessions()`. |
| `app.js` | API-strict helmet CSP; CORS allow-list; health mounted before sessions; `express-session`; 100 kb body limit. |
| `server.js` | Admin bootstrap, blockchain status line, cleaner shutdown. |
| `controllers/authController.js`, `routes/authRoutes.js` | The scrypt stub is replaced by real Phase 1 auth. |
| `controllers/healthController.js`, `routes/healthRoutes.js` | `blockchain` is now checked for real (RPC plus contract code) instead of "env vars set". Adds `/health/live` and `/health/ready`. |
| `controllers/communityController.js`, `routes/communityRoutes.js` | Per-type target validation, masked display, one vote per voter, admin status endpoint, single GET. |
| `controllers/registryController.js`, `routes/registryRoutes.js` | The stub (whose verify always answered "match") is replaced by real on-chain register/verify. The feed no longer invents defaults (`'suspicious'`, `'phishing'`, `providers`). |
| `jobs/investigationQueue.js` | Message pipeline (Phase 4). The raw message is dropped after analysis. |
| `services/aiExplainer.js`, `services/reportBuilder.js` | Message-specific template wording. Message text is never passed to the explainer. |
| `services/threatIntel/urlhausClient.js` | An unknown `query_status` (e.g. a missing Auth-Key) was treated as **no_match**. It is now `error`, so it never counts as clean. |
| `services/ssrfValidator.js` | DNS failure message no longer exposes `getaddrinfo` internals. |
| `middleware/rateLimiter.js` | Register, CSRF-token, vote, registry and verify limiters; failed-only login counting; test reset helper. |
| `middleware/errorHandler.js` | `413 PAYLOAD_TOO_LARGE`. Expected 4xx errors are logged at debug level without query strings. |
| `middleware/validate.js` | Cleaner message when the error has no field path. |
| `utils/logger.js` | Debug output only in development or when `LOG_LEVEL=debug`. |
| `package.json` | Adds `express-session` and `argon2`; dev dependency `supertest`; zod upgraded 3 → 4 (security advisory, no code changes needed); test script uses `test/setup.js`. |

### Changed tests (intentional behaviour changes)

| Test | Change |
|---|---|
| `phase0`: auth stub test | Now an HTTP flow with CSRF. |
| `phase6`: "message marks failed" | Now asserts the completed Phase 4 flow. |
| `phase6`: "no leaks" test | Its failed state is produced by a throwing job instead of a message. |
| `phase6` | Sets its own GSB test key. Previously four tests only passed with a real key in `.env`. |
| `health`: "all up" | Stubs the new real blockchain ping. |

## Supabase (done)

The Supabase repository is implemented. Setup steps are in [DATABASE.md](DATABASE.md).

- `src/store/supabaseRepository.js`: same contract as `MemoryRepository`.
- `src/store/dbCheck.js`: schema check at startup; marks interrupted scans as failed.
- `src/store/supabaseKey.js`: refuses the anon key.
- `supabase/schema.sql`: `cl_` tables, Row Level Security on, atomic merge function.
- `scripts/db-check.js` (`npm run db:check`).
- `test/db_provider.test.js`: 6 tests.

## Repository contract (for anyone changing the database)

- Keep the async repository contract.
- Sessions use `createSession(id, { userId, data, expiresAt })`, `getSession` and `deleteSession`. `data` is the JSON-serialised session; store it as text.
- Users need `updateUser(id, changes)`. Sessions should either expire automatically or support `pruneExpiredSessions()`.
- Registry entries now carry these fields:
  - `kind` (`investigation` | `community`) and `status` (`registered` | `pending` | `failed`);
  - `txStatus`, `reportHash`, `canonicalVersion`, `network`, `contractAddress`;
  - `txHash`, `blockNumber`, `timestamp`, `revision`, `explorerUrl`;
  - feed metadata: `classification`, `providers`, `intelMatches`, `category`.
