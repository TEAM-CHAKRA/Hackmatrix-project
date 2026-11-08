# CYBERLENS API — additions in Phases 1, 4, 7 and 8

The base contract is `docs/api-contract.md` (repo root). This file documents what the merged backend adds or tightens. All responses use the standard envelope:

```json
{ "success": true, "...": "payload" }
{ "success": false, "error": { "code": "…", "message": "user-safe text", "details": {} } }
```

## Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `VALIDATION_ERROR` | 400 | Bad input; `details` per field |
| `SSRF_BLOCKED` | 400 | Target resolves to a private or restricted address |
| `NOT_AUTHENTICATED` | 401 | Not signed in, or session expired or invalid |
| `INVALID_CREDENTIALS` | 401 | Wrong email or password (always the same generic message) |
| `FORBIDDEN` | 403 | Signed in but the role is not allowed |
| `CSRF_INVALID` | 403 | Missing or wrong `X-CSRF-Token`, or an untrusted Origin |
| `NOT_FOUND` | 404 | Unknown resource |
| `CONFLICT` | 409 | State does not allow it (e.g. registering an unfinished report) |
| `EMAIL_TAKEN` | 409 | Email already registered |
| `PAYLOAD_TOO_LARGE` | 413 | Body over `JSON_BODY_LIMIT` |
| `RATE_LIMITED` | 429 | Too many requests; `Retry-After` header is set |
| `CHAIN_UNAVAILABLE` | 503 | Blockchain not configured or unreachable (never faked) |
| `NOT_READY` | 503 | Readiness probe failed |
| `INTERNAL` | 500 | Unexpected error; details stay in server logs |

## Sessions and CSRF (Phase 1)

- **Session cookie** `cyberlens.sid`:
  - httpOnly, `SameSite=Lax`, Secure in production;
  - sliding 8-hour expiry;
  - session data is stored through the repository, never in the cookie.
- **Session ID** is regenerated on every login or registration. Logout destroys the session.
- **State-changing routes marked CSRF** need `X-CSRF-Token`. The token comes from `GET /api/auth/csrf`, or from the `csrfToken` field returned by login, register and `/me`.
- **Origin check**: when the browser sends `Origin`/`Referer`, it must be listed in `FRONTEND_URL`.
- **Frontend**: `frontend/src/services/api.js` already handles all of this, retrying once on `CSRF_INVALID`.

| Route | CSRF | Auth | Rate limit (per IP) |
|---|---|---|---|
| `GET /api/auth/csrf` | — | public | 300 / 15 min |
| `POST /api/auth/register` | ✔ | public | 5 / 15 min |
| `POST /api/auth/login` | ✔ | public | 5 failed / 15 min |
| `POST /api/auth/logout` | ✔ if signed in | — | — |
| `GET /api/auth/me` | — | signed in | — |
| `POST /api/investigations` | — | public | 30 / 10 min |
| `POST /api/community/reports` | ✔ | public (optional user) | 10 / 15 min |
| `POST /api/community/reports/:id/vote` | ✔ | public (optional user) | 60 / 15 min |
| `PATCH /api/community/reports/:id/status` | ✔ | **admin** | — |
| `POST /api/registry/register` | — | public | 10 / hour |
| `POST /api/registry/verify` | — | public | 60 / 10 min |

### Auth payloads

- **Register**: `{ fullName, email, password, acceptTerms: true }`, optionally with `confirmPassword`.
  - Unknown fields are rejected, so a client cannot set `role`, `id` or `passwordHash`.
  - Password rules: 8–128 characters, at least one letter and one number, not a common password, and not the email address.
- **Register** returns `201 { user, csrfToken }` and signs the user in.
- **Login** returns `200 { user, csrfToken }`.
- **`/me`** returns `200 { user, csrfToken }`.
- **`user`** is `{ id, fullName, email, role, createdAt }`. It never includes the password hash.

### Health

- `GET /api/health`: provider status `ok | degraded`, plus a `services` map (contract). `blockchain` is `ok` only when the RPC answers and the contract has code at the configured address.
- `GET /api/health/live`: always `200` while the process responds.
- `GET /api/health/ready`: `200` when the repository, session store and essential config are OK; otherwise `503 NOT_READY`.

## Message investigations (Phase 4)

`POST /api/investigations { "type": "message", "content": "…10–5000 chars…" }` returns `202`. Poll `GET /api/investigations/:id` as for URLs.

**Checks** (coverage total is 4):

| Check | What it does | Status values |
|---|---|---|
| `indicators` | Extracts URLs (including defanged `hxxp`/`[.]`), domains, emails and phones | always `completed` |
| `tactics` | Finds urgency, threat, impersonation, fake_reward, account_suspension, otp_request, password_request, payment_request, suspicious_link and social_engineering | `completed` |
| `threat_intel` | Looks up the extracted links (up to 5) in Google Safe Browsing and URLhaus | `match_found` / `no_match` / `unavailable`; `not_checked` when the message has no links |
| `links` | Compares the claimed brand with the link domain; flags raw IPs, shorteners, punycode and plain HTTP | `completed`; `not_checked` when there are no links |

Classification rules:
- `confirmed_malicious` only when GSB or URLhaus matched an extracted link.
- Language and link findings alone can reach `high_risk` at most.
- Steps: `tls_security` is `skipped` for messages.

`report.message` contains:
- `highlights`: `[{ start, end, phrase, tactic }]`, offsets into the original text, never overlapping;
- `indicators`: links are shown with sensitive query values redacted;
- `tactics`: `[{ key, count }]`.

Privacy: the raw message text is deleted from the record when the analysis finishes. Only extracted URLs are sent to providers, and only finding titles are sent to the AI.

## Community reports (Phase 7)

| Route | Body | Result |
|---|---|---|
| `POST /api/community/reports` | `{ targetType: url\|domain\|phone\|email, target, category, description (20–1000) }` | `201 { report: { id, status: "pending_review" } }` |
| `GET /api/community/reports` | — | `{ items: [...] }`; rejected reports are hidden (admins see all) |
| `GET /api/community/reports/:id` | — | `{ report }` |
| `POST /api/community/reports/:id/vote` | `{ voteType: confirm\|dispute }` | `{ report: { id, status, validation, yourVote, changed } }` |
| `PATCH /api/community/reports/:id/status` | `{ status, linkedInvestigationId? }` | admin only |

- **Target validation** depends on the type: http(s) URL, domain, email or phone.
- **`targetDisplay`** is redacted:
  - URLs show only host and path (no query or credentials);
  - emails and phone numbers are masked.
- **Votes**: one per voter (the signed-in user, or a salted hash of the IP). A voter can switch their vote. Three or more votes move a report from `pending_review` to `under_review`.
- **Status**: only admins can set `validated`, `disputed` or `rejected`.
- **Classification**: community reports never receive a risk classification.

## Registry and on-chain integrity (Phase 8)

**`POST /api/registry/register`** takes `{ investigationId }` or `{ communityReportId }` (validated community reports only).
- Only **completed** investigations can be registered; otherwise `409 CONFLICT`.
- It is idempotent: a repeat call returns the stored receipt and sends no new transaction. Concurrent calls share a single transaction.
- `status: "registered"` is returned **only with a mined receipt**.
- If mining takes longer than `CHAIN_TX_TIMEOUT_MS`, it returns `status: "pending"` with the `txHash`; calling again checks the receipt.
- If the backend restarted after an earlier registration, the record is recovered from the contract (the original `txHash` is found through the contract event) instead of being sent again.
- If the chain is unreachable, it returns `503 CHAIN_UNAVAILABLE` and the report's `registry.status` becomes `failed`, so the UI offers a retry.

**`POST /api/registry/verify`** takes `{ investigationId }` or `{ reportHash }` (64 hex characters, `0x` optional).
- It recomputes the canonical hash from the stored report and compares it with the hash **read from the contract**.
- `integrity` is one of:
  - `match`;
  - `mismatch` (the report changed, or the hash belongs to an older revision);
  - `not_registered`.
- It also returns `computedHash`, `onChainHash`, `blockNumber`, `timestamp`, `revision`, `onChainStatus` and `txHash`.

**`GET /api/registry`** is the Threat Feed: registered investigations only.
- `providers` lists only the providers that actually completed.
- `intelMatches` lists only real matches.
- `category` is derived from the match types, or `null`.
- No raw URLs or message text are included.

**Canonical snapshot** (`cyberlens-report/v1`):
- Included: id, type, analyzedAt, target display/host, classification, confidence, heuristicScore, coverage, `checks[{id,status}]`, `findings[{id,title,severity,category,checkId,source}]`, a TLS/headers status summary, and message tactic and indicator *counts*.
- Excluded: `demo`, `steps`, `status`, `registry`, timestamps used for polling, raw text, evidence, descriptions and the AI narrative.
- Keys are sorted and the result is hashed with SHA-256. The exact string is stored with `repository.storeCanonicalSnapshot`.

**Contract** (`contracts/contracts/CyberlensRegistry.sol`):
- Registration is idempotent for the same ID and hash.
- `reviseReport` increases the revision number.
- A hash cannot be reused for a different ID.
- `updateStatus` is owner-only.
- Writes are restricted to authorised registrars (prevents front-running an ID with a fake hash).
- Lookups work by ID and by hash.
