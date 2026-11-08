# CYBERLENS API Contract (v0.1 — frontend-driven draft)

> Owner: **Member 2 (Backend)**. This draft is what the frontend currently consumes.
> Change it only by agreement, and update `frontend/src/services/mock/fixtures.js` to match.
> All examples are **illustrative shapes**, not real investigation results.

Base path: `/api`. JSON only. In dev, Vite proxies `/api` → `http://localhost:4000`.

## Conventions

**Success:** `{ "success": true, ... }`

**Error (any non-2xx):**
```json
{ "success": false, "error": { "code": "VALIDATION_ERROR", "message": "Human-readable message", "details": {} } }
```
Codes used by the UI: `VALIDATION_ERROR` (400), `SSRF_BLOCKED` (400), `NOT_FOUND` (404), `RATE_LIMITED` (429), `PROVIDER_ERROR` (502), `CHAIN_UNAVAILABLE` (503), `INTERNAL` (500). The frontend shows `error.message` directly, so keep it user-safe (no stack traces, no secrets).

### Shared enums (must match `frontend/src/utils/constants.js`)

| Name | Values |
|---|---|
| `classification` | `low_risk` · `suspicious` · `high_risk` · `confirmed_malicious` · `inconclusive` |
| `confidence` | `low` · `medium` · `high` |
| check `status` | `completed` · `no_match` · `match_found` · `unavailable` · `error` · `not_checked` |
| step `status` | `pending` · `running` · `completed` · `failed` · `skipped` |
| finding `severity` | `critical` · `high` · `medium` · `low` · `info` |
| finding `category` | `confirmed` (external TI / verified) · `heuristic` · `weakness` (e.g. missing headers) · `informational` |
| report `status` | `processing` · `completed` · `failed` |
| registry `status` | `not_registered` · `pending` · `registered` · `failed` |
| tls `status` | `valid` · `expired` · `hostname_mismatch` · `untrusted_chain` · `incomplete` · `unavailable` · `no_https` |
| message tactic keys | `urgency` · `threat` · `impersonation` · `fake_reward` · `account_suspension` · `otp_request` · `password_request` · `payment_request` · `suspicious_link` · `social_engineering` |

**Coverage rule:** `coverage.completed` counts checks whose status is `completed`, `no_match` or `match_found`. `unavailable` / `error` / `not_checked` are never counted and never treated as clean.

---

## POST `/api/investigations`

URL request: `{ "type": "url", "target": "https://example.com" }`
Message request: `{ "type": "message", "content": "Your account has been suspended..." }`

Validation: `target` must be http/https, ≤ 2048 chars, SSRF-checked server-side. `content` 10–5000 chars.

Response `202`:
```json
{ "success": true, "investigationId": "INV-20261107-7F3A2C", "status": "processing" }
```

## GET `/api/investigations/:id`

The frontend polls every 1.2 s while `report.status === "processing"`.

```jsonc
{
  "success": true,
  "report": {
    "id": "INV-20261107-7F3A2C",
    "type": "url",                         // "url" | "message"
    "status": "completed",                  // processing | completed | failed
    "createdAt": "2026-11-07T06:00:00Z",
    "completedAt": "2026-11-07T06:00:09Z",
    "demo": false,                          // true ONLY for fixtures
    "target": { "display": "https://example.com/?token=[redacted]", "host": "example.com" },

    // Always present (also while processing) so the stepper can render:
    "steps": [
      { "key": "submission",   "label": "Submission received",           "status": "completed" },
      { "key": "investigation","label": "URL investigation",             "status": "completed" },
      { "key": "threat_intel", "label": "Threat intelligence analysis",  "status": "running" },
      { "key": "tls_security", "label": "TLS and security assessment",   "status": "pending", "detail": "optional" },
      { "key": "risk_report",  "label": "Risk assessment and report",    "status": "pending" }
    ],
    "checks": [
      { "id": "gsb", "name": "Google Safe Browsing", "source": "Google Safe Browsing", "status": "no_match", "detail": "optional text" }
    ],

    // Present when completed:
    "classification": "low_risk",
    "confidence": "high",
    "heuristicScore": 6,                    // 0–100 or null. Heuristic, NOT a probability.
    "coverage": { "completed": 5, "total": 6 },
    "findings": [
      {
        "id": "f1",
        "title": "Content-Security-Policy header missing",
        "description": "…",
        "severity": "low",
        "category": "weakness",
        "source": "HTTP security header inspection",
        "checkId": "headers",               // links to checks[].id
        "evidence": { "Header": "Content-Security-Policy", "Observed": "Not present" } // object or string
      }
    ],
    "redirectChain": [                      // url reports only; query values redacted
      { "url": "http://example.com/", "statusCode": 301, "suspicious": false, "note": "optional" },
      { "url": "https://example.com/", "statusCode": 200, "suspicious": false }
    ],
    "tls": {                                // url reports only
      "status": "valid",
      "httpsAvailable": true, "valid": true,
      "validFrom": "ISO", "validTo": "ISO", "daysRemaining": 69,
      "issuer": "…", "subject": "CN=…", "san": ["example.com"],
      "hostnameMatch": true,
      "publicKey": { "type": "EC", "bits": 256 },
      "signatureAlgorithm": "ecdsa-with-SHA384",
      "chainTrusted": true,
      "chain": [ { "role": "leaf|intermediate|root", "subject": "…", "issuer": "…", "validTo": "ISO" } ],
      "ct": { "status": "completed|not_checked|error", "entries": 14, "note": "…" },
      "revocation": { "status": "not_checked" },
      "note": "used when status = unavailable"
    },
    "securityHeaders": {                    // url reports only
      "status": "completed",                // anything else => shows note
      "note": "…",
      "httpsRedirect": true,                // true | false | null (unknown)
      "headers": [ { "name": "Strict-Transport-Security", "present": true, "value": "max-age=…", "recommendation": "…" } ],
      "cookies": [ { "name": "sid", "secure": true, "httpOnly": true, "sameSite": "Lax" } ]
    },
    "message": {                            // message reports only
      "text": "optional — omit if not retained; frontend falls back to the tab's own copy",
      "highlights": [ { "start": 0, "end": 6, "phrase": "URGENT", "tactic": "urgency" } ], // offsets into the ORIGINAL submitted text, non-overlapping
      "indicators": { "urls": [], "domains": [], "emails": [], "phones": [] },
      "tactics": [ { "key": "urgency", "count": 2 } ]
    },
    "explanation": {
      "source": "ai",                       // "ai" | "template"
      "summary": "…",
      "keyPoints": ["…"]
    },
    "recommendations": ["…"],
    "limitations": ["…"],
    "registry": { "status": "not_registered" }   // see registry object below
  }
}
```

Failed investigation: `{ "status": "failed", "error": { "message": "…" }, "steps": [...] }`. The UI states that the target was **not assessed**.

---

## POST `/api/registry/register`

Request: `{ "investigationId": "INV-…" }` (frontend timeout 90 s)

Response:
```json
{
  "success": true,
  "registry": {
    "status": "registered",
    "reportHash": "64-hex sha256 of canonical snapshot",
    "canonicalVersion": "cyberlens-report/v1",
    "network": "Sepolia",
    "contractAddress": "0x…",
    "txHash": "0x…",
    "blockNumber": 1234567,
    "timestamp": "ISO",
    "explorerUrl": "https://sepolia.etherscan.io/tx/0x…",
    "revision": 1
  }
}
```
Return `status: "registered"` **only with a real mined receipt**. Otherwise `pending`, or an error response (`409 CONFLICT` if the report is not completed, `503 CHAIN_UNAVAILABLE` if no chain is reachable). `network` is `"Hardhat Local"` (explorerUrl `null`) or `"Sepolia"`.

## POST `/api/registry/verify`

Request: `{ "investigationId": "INV-…" }` **or** `{ "reportHash": "64-hex" }`

Response:
```json
{
  "success": true,
  "result": {
    "integrity": "match",                   // match | mismatch | not_registered
    "investigationId": "INV-…",
    "computedHash": "…",
    "onChainHash": "…",
    "canonicalVersion": "cyberlens-report/v1",
    "network": "Sepolia",
    "contractAddress": "0x…",
    "txHash": "0x…",
    "blockNumber": 1234567,
    "timestamp": "ISO",
    "explorerUrl": "https://…"
  }
}
```

## GET `/api/registry`

```json
{
  "success": true,
  "items": [
    {
      "investigationId": "INV-…",
      "classification": "suspicious",
      "registeredAt": "ISO",
      "txStatus": "confirmed",              // confirmed | pending | failed
      "txHash": "0x…",
      "explorerUrl": "https://…",
      "network": "Sepolia",
      "revision": 1,
      "category": "phishing",               // optional; see Threat categories below
      "providers": ["Google Safe Browsing", "URLhaus"],          // providers actually checked
      "intelMatches": [ { "provider": "Google Safe Browsing", "threatType": "SOCIAL_ENGINEERING" } ], // REAL matches only, [] if none
      "validationStatus": null              // optional
    }
  ]
}
```
Used by the **Threat Feed** (`/threat-feed`). Never include raw URLs or message text here.

---

## Community reports (Community page + Threat Feed)

Community reports are **always unverified** and are never given a risk classification by themselves.

### GET `/api/community/reports`
```json
{
  "success": true,
  "items": [
    {
      "id": "CR-…",
      "category": "impersonation",
      "targetDisplay": "sbi-kyc-update.example",   // redacted / safe-to-display form
      "description": "…",
      "submittedAt": "ISO",
      "status": "pending_review",                  // pending_review | under_review | validated | disputed | rejected
      "validation": { "confirms": 3, "disputes": 1 },   // optional
      "registry": { "status": "registered", "txHash": "0x…", "explorerUrl": "https://…" }, // optional
      "linkedInvestigationId": "INV-…"             // optional
    }
  ]
}
```

### POST `/api/community/reports`
Request:
```json
{ "targetType": "url", "target": "https://…", "category": "phishing", "description": "20–1000 chars" }
```
`targetType`: `url | domain | phone | email`. Validate server-side (SSRF rules do not apply: the target is stored, not fetched).
Response `201`: `{ "success": true, "report": { "id": "CR-…", "status": "pending_review" } }`.
Submissions are anonymous-friendly (no login needed) but send `X-CSRF-Token` like every POST.

Also available: `GET /api/community/reports/:id`, `POST /api/community/reports/:id/vote { voteType: "confirm" | "dispute" }` (one vote per voter), and admin-only `PATCH /api/community/reports/:id/status`. Validated community reports can be anchored with `POST /api/registry/register { communityReportId }`. Details: `backend/docs/API.md`.

Threat categories: `phishing | scam | malware | impersonation | fake_shop | investment_fraud | other`.

---

## Authentication

Session = **httpOnly, Secure, SameSite=Lax cookie** set by the backend. The frontend sends `credentials: 'include'` and never stores tokens or passwords.
Hash passwords with bcrypt/argon2. Rate-limit login. If frontend and backend are on different origins, enable CORS with `credentials: true` and an explicit origin allow-list.

| Endpoint | Request | Success | Errors |
|---|---|---|---|
| `GET /api/auth/csrf` | — | `200 { success, csrfToken }` | — |
| `POST /api/auth/register` | `{ fullName, email, password, acceptTerms: true }` | `201 { success, user, csrfToken }` + Set-Cookie (signs in) | `400` validation, `403` CSRF, `409` email exists, `429` |
| `POST /api/auth/login` | `{ email, password }` | `200 { success, user, csrfToken }` + Set-Cookie | `401` invalid credentials, `403` CSRF, `429` |
| `POST /api/auth/logout` | — | `200 { success }`, clears cookie (idempotent) | `403` CSRF when signed in |
| `GET /api/auth/me` | — | `200 { success, user, csrfToken }` | `401` not signed in |

`user`: `{ id, fullName, email, role, createdAt }`. Never return password hashes. Not signed in → `401 NOT_AUTHENTICATED`; wrong credentials → `401 INVALID_CREDENTIALS`.

**CSRF:** state-changing requests send `X-CSRF-Token` (token from `GET /api/auth/csrf` or any `csrfToken` field); the Origin must be an allowed frontend origin. `403 CSRF_INVALID` → fetch a new token and retry once. Implemented in `frontend/src/services/api.js`. Full details: `backend/docs/PHASE_1_API.md`.

## GET `/api/health`

```json
{
  "success": true,
  "status": "ok",                           // ok | degraded | down (503)
  "services": { "database": "ok", "googleSafeBrowsing": "ok", "urlhaus": "ok", "crtsh": "ok", "ai": "unavailable", "blockchain": "ok" }
}
```
Never include keys, RPC URLs with tokens, or wallet addresses' private material.
Also available: `GET /api/health/live` (liveness) and `GET /api/health/ready` (readiness, 503 when a critical dependency is down). See `backend/docs/PHASE_1_API.md`.
