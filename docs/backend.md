## AMENDMENTS (these override anything below that conflicts)

1. Storage: use an in-memory repository (`src/store/repository.js`) for now.
   Do NOT add Prisma or SQLite yet. Another teammate owns the database and
   will replace the repository later. Routes and services must only call
   the repository, never a database directly.
2. Priorities: Phases 2, 3, 5, 6 and 8 are P0. Authentication (Phase 1)
   and community reports (Phase 7) are P1. Build auth last.
3. IDs: investigation and community IDs use at least 16 random hex
   characters (crypto.randomBytes), e.g. INV-20261107-<16hex>.
4. Rate limiting applies to POST /api/investigations as well as login.
5. SSRF (Phase 2):
   - Resolve once, validate every returned IP, then CONNECT TO THE
     VALIDATED IP (custom lookup/agent). Never resolve twice.
   - The TLS inspector must also connect to the validated IP and set
     `servername` to the hostname.
   - Also block ::, IPv4-mapped IPv6 (::ffff:x.x.x.x), and unusual IP
     encodings (decimal, octal, hex). Allow only ports 80 and 443,
     including on redirects.
6. URL checks (6 total, fixed IDs for coverage): gsb, urlhaus, domain,
   tls, ct, headers. Message checks (4 total): indicators, tactics,
   threat_intel, links. Unavailable/error/not_checked never count.
7. Add a domain analyzer: punycode/homoglyph detection, typosquatting
   against a list of target brands, brand-in-subdomain detection, and
   domain age/registrar via RDAP.
8. TLS: add `tls.distrust` { status: no_match|match_found|not_checked,
   source, note } using a small maintained list of known compromised or
   distrusted CAs, and add `weak_crypto` to the tls status values.
   Never claim to detect CA key-generation flaws from a URL.
9. AI rules: the LLM never sets the classification. It receives
   structured evidence only (never raw page content), treats all text as
   untrusted, and its JSON output is validated against a schema; on any
   failure use the template fallback. Send redacted or derived message
   data, not the full raw message, to external AI services.
10. Hashing: exclude `demo`, `steps`, `status`, `registry`, polling
    fields and raw message text from the canonical snapshot. Store the
    exact snapshot that was hashed. `register` must be idempotent.
11. Contracts: add a separate `contracts/` Hardhat project (contract,
    tests, deploy script) before Phase 8. The contract supports lookup
    by investigation ID and by hash, revisions, and status
    (registered, validated, disputed). Only hashes go on-chain, no
    free-text metadata. Test on a local Hardhat node first.
12. Community: allow anonymous submissions with rate limiting. Add a
    vote/status endpoint and allow community reports to be registered.
13. Secrets: never commit .env. Use a throwaway wallet for Sepolia.
14. Contract (Phase 8) must be fixed before implementation:
    - updateStatus must be restricted (owner/admin only).
    - Add a real revision flow (reviseReport) instead of reverting on a
      different hash. Revision numbers must increase.
    - Reject registering a hash already used by a different ID.
    - Support a local Hardhat chain: add CHAIN_MODE (local|sepolia) and
      LOCAL_RPC_URL to .env.example; explorerUrl is null on local.
15. confirmed_malicious comes ONLY from gsb or urlhaus returning
    match_found. A TLS distrust match, domain findings, or community
    reports never produce confirmed_malicious on their own (they raise
    high_risk or suspicious).
16. For message investigations, mark the tls_security step "skipped",
    not "pending", so the stepper doesn't wait forever.
17. The distrusted-CA list must cite a source and date per entry. Verify
    the eMudhra incident details before adding it to the list or the pitch.
    Never claim to detect key-generation flaws from a URL.
18. Prefer bcryptjs over argon2 if the native build fails on Windows.
19. Stub GET /api/auth/me in Phase 0: return 401 NOT_AUTHENTICATED in the
    standard error envelope until real auth exists. The frontend calls it
    on every page load.
    20. Phase 2 additions: reject URL credentials; follow 303 as well as
    301/302/307/308; detect redirect loops; 1 MB response cap and 8s timeout;
    no cookies or auth headers; block 64:ff9b::/96. The pinned lookup must
    handle options.all (return an array of {address, family}) and the agent
    must set autoSelectFamily: false. Keep the original hostname for the
    Host header and TLS servername.
20. Repository is async: every method in src/store/repository.js returns a Promise and every caller must 
    await it. Returned records are plain JSON-safe data (dates as ISO strings, no Map/Set/class 
    instances) and are copies, not references to stored objects. A teammate will later replace the 
    in-memory implementation with Supabase; routes and services must keep working without changes. 
    Not-found returns null. Canonical snapshots are stored and returned as the exact string.
21. IDs are looked up case-insensitively (one canonical case internally). INV-...ABC and INV-...abc 
    resolve to the same record.

# CYBERLENS Backend Implementation Specification & Roadmap

> **Document Version:** 1.1.0 (Harmonized with Architecture Amendments)  
> **Target Base Path:** `/api` (Port: `4000`, proxied via Vite dev server `http://localhost:5173/api`)  
> **Source Contract:** [docs/api-contract.md]
> **Frontend Reference:** [frontend/src/services/api.js]& [frontend/src/services/mock/fixtures.js] 
> **Assigned To:** Member 2 (Backend Lead)

---

## 1. Executive Summary & Architecture Overview

CYBERLENS is an AI-powered digital trust and web threat intelligence platform. The backend service acts as an orchestration engine that safely inspects targets, executes external threat intelligence lookups, performs TLS and security audits, analyzes natural language phishing indicators, arbitrates heuristic risk scores, and anchors canonical cryptographic snapshots to the Ethereum Sepolia blockchain.

### Architectural Core Principles (incorporating Amendments)
- **Zero Database Direct Access (In-Memory Repository):** No Prisma, no SQLite, and no `prisma/` folder. All state is held in an in-memory repository (`src/store/repository.js`). Routes and services interact strictly with repository abstraction methods so another team member can plug in the persistent database later without changing business logic.
- **Strict SSRF Immunity & DNS Pinning:** Resolve once, validate all returned IPs, and connect directly to the validated IP. Never resolve twice (immune to DNS rebinding). Block loopback, private ranges, link-local, AWS/GCP metadata, `::`, IPv4-mapped IPv6 (`::ffff:x.x.x.x`), and alternate IP encodings (octal, decimal, hex). Enforce ports 80 and 443 exclusively.
- **Coverage Rule Integrity:** URL investigations consist of **6 fixed checks** (`gsb`, `urlhaus`, `domain`, `tls`, `ct`, `headers`). Message investigations consist of **4 fixed checks** (`indicators`, `tactics`, `threat_intel`, `links`). `coverage.completed` counts only `completed`, `no_match`, and `match_found`. `unavailable`, `error`, and `not_checked` NEVER count towards coverage and are NEVER treated as clean.
- **Separation of AI & Classification:** The LLM **never** determines classification or heuristic scores. It receives only structured, sanitized evidence (never raw page content or raw messages). If the LLM times out or fails JSON schema validation, deterministic template generation seamlessly takes over.
- **Deterministic Blockchain Anchoring:** Canonical snapshots exclude transient UI states (`demo`, `steps`, `status`, `registry`, polling fields, and raw message text). The exact hashed snapshot is preserved for verifiable on-chain audits. `register` is strictly idempotent.
- **Secure ID Generation:** All investigation and community IDs use at least 16 cryptographically secure random hex characters (`crypto.randomBytes(8).toString('hex')`), e.g., `INV-YYYYMMDD-<16hex>` and `CR-YYYYMMDD-<16hex>`.

```
                              ┌──────────────────────────────────┐
                              │     CYBERLENS Frontend (React)   │
                              └─────────────────┬────────────────┘
                                                │ /api (Vite Proxy)
                                                ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                Node.js / Express API Server                             │
│  ┌────────────────────┐   ┌───────────────────────────┐   ┌─────────────────────────┐  │
│  │   Auth & Session   │   │  SSRF-Safe Pinned Client  │   │  Async Job Orchestrator │  │
│  │ (Cookies / Argon2) │   │ (Single DNS resolve, CIDs)│   │  (Worker / Steps State) │  │
│  └─────────┬──────────┘   └─────────────┬─────────────┘   └────────────┬────────────┘  │
│            │                            │                              │               │
│            ▼                            ▼                              ▼               │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │              In-Memory Repository Interface (src/store/repository.js)            │  │
│  │      [Users]       [Investigations]       [CommunityReports]       [Registry]     │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────┼──────────────────────────────┼───────────────┘
                                          │                              │
                ┌─────────────────────────┴───────────────┐              │
                ▼                                         ▼              ▼
     ┌──────────────────────┐                  ┌──────────────────────────────┐
     │ External TI & Audits │                  │ Verification & Blockchain    │
     ├──────────────────────┤                  ├──────────────────────────────┤
     │ • Google Safe Brows. │                  │ • Heuristic Risk Arbiter     │
     │ • URLhaus (abuse.ch) │                  │ • AI Explainer + Templates   │
     │ • RDAP Domain Info   │                  │ • Canonical Hasher (SHA-256) │
     │ • Node TLS Handshake │                  │ • Hardhat Contracts Project  │
     │ • crt.sh CT logs     │                  │ • Sepolia Web3 / Ethers.js   │
     └──────────────────────┘                  └──────────────────────────────┘
```

---

## 2. Shared Enums & Data Types Reference

All enums align 100% with `docs/api-contract.md` and `frontend/src/utils/constants.js`:

| Enum Name | Allowed Values |
|---|---|
| `classification` | `low_risk`, `suspicious`, `high_risk`, `confirmed_malicious`, `inconclusive` |
| `confidence` | `low`, `medium`, `high` |
| check `status` | `completed`, `no_match`, `match_found`, `unavailable`, `error`, `not_checked` |
| step `status` | `pending`, `running`, `completed`, `failed`, `skipped` |
| finding `severity` | `critical`, `high`, `medium`, `low`, `info` |
| finding `category` | `confirmed` (external TI/verified), `heuristic`, `weakness` (e.g. missing headers), `informational` |
| report `status` | `processing`, `completed`, `failed` |
| registry `status` | `not_registered`, `pending`, `registered`, `failed` |
| tls `status` | `valid`, `expired`, `hostname_mismatch`, `untrusted_chain`, `incomplete`, `unavailable`, `no_https`, `weak_crypto` |
| tls `distrust.status` | `no_match`, `match_found`, `not_checked` |
| community report `status` | `pending_review`, `under_review`, `validated`, `disputed`, `rejected` |
| message tactic keys | `urgency`, `threat`, `impersonation`, `fake_reward`, `account_suspension`, `otp_request`, `password_request`, `payment_request`, `suspicious_link`, `social_engineering` |
| threat categories | `phishing`, `scam`, `malware`, `impersonation`, `fake_shop`, `investment_fraud`, `other` |

---

## 3. Step-by-Step Implementation Roadmap (By Phases)

---

### Phase 0: Setup, Project Layout & In-Memory Storage Abstraction [P0]

**Goal:** Establish the Express server on port 4000, build the in-memory repository abstraction, configure error handling envelopes, and set up rate limiting.

#### 1. Tech Stack Selection
- **Runtime:** Node.js (v20+ LTS)
- **Framework:** Express.js (ESM)
- **Data Layer:** In-memory repository (`src/store/repository.js`). **Zero database or Prisma dependencies.**
- **Validation:** `zod` for request schemas
- **Security & Session:** `cookie-parser`, `cors`, `helmet`, `argon2`, `express-rate-limit`
- **Networking & Cryptography:** Native `node:tls`, `node:dns`, `node:crypto`, `node:http`, `node:https`, `undici`
- **Blockchain Interface:** `ethers` (v6)

#### 2. Project Directory Layout
```
contracts/                       # Dedicated Hardhat project for Sepolia contract
├── contracts/
│   └── CyberlensRegistry.sol    # Smart contract with ID/hash lookup, revisions, status
├── scripts/
│   └── deploy.js                # Deployment script for local node and Sepolia
├── test/
│   └── CyberlensRegistry.test.js# Hardhat contract tests
├── hardhat.config.js
└── package.json

backend/
├── src/
│   ├── app.js                   # Express application setup & middleware assembly
│   ├── server.js                # HTTP server listening on port 4000
│   ├── config/
│   │   ├── env.js               # Validated env vars via Zod
│   │   └── constants.js         # Ported enums, check IDs, and fixed limits
│   ├── store/
│   │   └── repository.js        # IN-MEMORY REPOSITORY (All state stored here)
│   ├── middleware/
│   │   ├── auth.js              # Session cookie validator
│   │   ├── errorHandler.js      # Global error handler with contract envelopes
│   │   ├── rateLimiter.js       # Rate limiters for investigations, login, and community
│   │   └── validate.js          # Request payload validator
│   ├── controllers/
│   │   ├── investigationController.js
│   │   ├── healthController.js
│   │   ├── registryController.js
│   │   ├── communityController.js
│   │   └── authController.js
│   ├── routes/
│   │   ├── investigationRoutes.js
│   │   ├── healthRoutes.js
│   │   ├── registryRoutes.js
│   │   ├── communityRoutes.js
│   │   └── authRoutes.js
│   ├── services/
│   │   ├── ssrfValidator.js     # IP blacklisting, encoding checks, and pinned resolver
│   │   ├── safeHttpClient.js    # Single-resolve pinned HTTP client, redirect & query scrubber
│   │   ├── domainAnalyzer.js    # Punycode, homoglyphs, typosquatting, subdomains, RDAP
│   │   ├── tlsInspector.js      # Raw TLS handshake to validated IP, distrust check, weak_crypto
│   │   ├── ctService.js         # Certificate Transparency (crt.sh) client with 8s timeout
│   │   ├── threatIntel/
│   │   │   ├── gsbClient.js     # Google Safe Browsing v4 API
│   │   │   └── urlhausClient.js # abuse.ch URLhaus API
│   │   ├── messageAnalyzer.js   # Indicator extractor & non-overlapping tactic highlighter
│   │   ├── heuristicEngine.js   # Scoring arbiter & classification logic (LLM independent)
│   │   ├── aiExplainer.js       # Structured-input LLM generator + deterministic templates
│   │   ├── canonicalHasher.js   # Canonical JSON snapshot serializer and SHA-256 hasher
│   │   └── blockchainService.js # Sepolia contract bridge (calls Hardhat contract)
│   ├── jobs/
│   │   └── investigationQueue.js# In-memory async worker with step progress tracking
│   └── utils/
│       ├── idGenerator.js       # Generates INV-... and CR-... with 16 random hex chars
│       ├── logger.js            # Structured logger (sanitizes tokens/secrets)
│       └── response.js          # Standard success/error response helpers
├── .env.example
├── package.json
└── README.md
```

#### 3. In-Memory Repository Specification (`src/store/repository.js`)
The repository is an in-memory data store holding all platform entities. Routes and services must **only** interact with this interface:
```javascript
// src/store/repository.js
export class MemoryRepository {
  constructor() {
    this.investigations = new Map(); // id -> investigation
    this.canonicalSnapshots = new Map(); // id -> exact canonical snapshot string
    this.communityReports = new Map(); // id -> community report
    this.registryEntries = new Map(); // investigationId -> registry entry
    this.users = new Map(); // id -> user
    this.usersByEmail = new Map(); // email -> user
    this.sessions = new Map(); // sessionId -> { userId, expiresAt }
  }

  // --- Investigations ---
  createInvestigation(record) { ... }
  getInvestigation(id) { ... }
  updateInvestigation(id, updates) { ... }
  storeCanonicalSnapshot(id, snapshotString) { ... }
  getCanonicalSnapshot(id) { ... }

  // --- Registry ---
  createRegistryEntry(entry) { ... }
  getRegistryEntryByInvestigationId(invId) { ... }
  getRegistryEntryByHash(reportHash) { ... }
  listRegistryEntries() { ... }

  // --- Community Reports ---
  createCommunityReport(report) { ... }
  getCommunityReport(id) { ... }
  listCommunityReports() { ... }
  voteCommunityReport(id, { voteType }) { ... } // confirms or disputes
  updateCommunityReport(id, updates) { ... }

  // --- Authentication & Users ---
  createUser(user) { ... }
  getUserById(id) { ... }
  getUserByEmail(email) { ... }
  createSession(sessionId, sessionData) { ... }
  getSession(sessionId) { ... }
  deleteSession(sessionId) { ... }
}

export const repository = new MemoryRepository();
```

#### 4. ID Generation Utility (`src/utils/idGenerator.js`)
- Must use at least 16 random hex characters via `crypto.randomBytes(8).toString('hex')`.
- Investigation IDs: `INV-YYYYMMDD-<16_HEX_CHARS>` (e.g. `INV-20261107-7f3a2c9d1e4b8a5f`).
- Community Report IDs: `CR-YYYYMMDD-<16_HEX_CHARS>` (e.g. `CR-20261107-a91b3c4d5e6f7a8b`).

#### 5. Standardized Response Helpers & Rate Limiting
- `sendSuccess(res, data, statusCode = 200)`: `{ success: true, ...data }`.
- `sendError(res, { code, message, details }, statusCode = 400)`: `{ success: false, error: { code, message, details: details || {} } }`.
- Rate limiting (`express-rate-limit`):
  - `POST /api/investigations`: Max 30 requests per 10 minutes per IP.
  - `POST /api/auth/login`: Max 5 attempts per 15 minutes per IP.
  - `POST /api/community/reports`: Max 10 requests per 15 minutes per IP.

---

### Phase 2: SSRF Shield, DNS Pinning & Safe Network Client [P0]

**Goal:** Provide bulletproof SSRF immunity, eliminate DNS rebinding, block prohibited encodings, and connect strictly to pre-validated IP addresses.

#### 1. Target Validation & Port Enforcement
- Protocol must strictly be `http:` or `https:`.
- Port must strictly be `80` or `443` (reject `http://example.com:8080`, `https://example.com:8443`, etc.).
- Target length $\le 2048$ characters.

#### 2. Advanced SSRF & IP Encoding Validator (`src/services/ssrfValidator.js`)
- **Block Alternate IP Encodings in Hostname:**
  - Reject decimal IPs (e.g., `http://2130706433/`).
  - Reject octal IPs (e.g., `http://0177.0.0.1/`).
  - Reject hex IPs (e.g., `http://0x7f.0x0.0x0.0x1/`).
  - Reject pure numeric hostnames that could be converted to IPs.
- **Single DNS Resolution & Comprehensive Blacklist:**
  - Perform DNS lookup **once** using `dns.promises.lookup(hostname, { all: true })`.
  - Validate **every** resolved IPv4 and IPv6 address against:
    - `0.0.0.0/8` (current network)
    - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (private networks)
    - `127.0.0.0/8` (loopback)
    - `169.254.0.0/16` (link-local, cloud metadata `169.254.169.254`)
    - `100.64.0.0/10` (carrier-grade NAT)
    - `192.0.0.0/24`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (test/documentation)
    - `224.0.0.0/4`, `240.0.0.0/4` (multicast/reserved)
    - `::` (IPv6 unspecified)
    - `::1` (IPv6 loopback)
    - `::ffff:0:0/96` (IPv4-mapped IPv6, e.g. `::ffff:127.0.0.1`)
    - `fc00::/7` (IPv6 unique local)
    - `fe80::/10` (IPv6 link-local)
- If any resolved IP fails validation, immediately abort with HTTP `400`:
  ```json
  { "success": false, "error": { "code": "SSRF_BLOCKED", "message": "The requested target resolves to a private or restricted network address.", "details": {} } }
  ```

#### 3. Pinned Safe HTTP Client (`src/services/safeHttpClient.js`)
- **DNS Pinning:** Connect to the **validated IP directly** via a custom agent / custom lookup:
  ```javascript
  const agent = new http.Agent({
    lookup: (hostname, options, callback) => {
      // Return the pre-validated IP address directly. Never re-resolve DNS!
      callback(null, validatedIp, isIPv6 ? 6 : 4);
    }
  });
  ```
- **Redirect Chain Tracker:**
  - Follow max 5 hops.
  - On each redirect (`301`, `302`, `307`, `308`), inspect the new target:
    - Enforce port 80 or 443 only.
    - Run single DNS resolve + IP validation on the new host before making the next connection.
  - Scrub sensitive query parameters (`token`, `session`, `auth`, `key`, `password`, `sig`, `code`) $\rightarrow$ replace with `[redacted]`.
  - Record each hop in `redirectChain: [{ url, statusCode, suspicious, note }]`.

---

### Phase 3: Threat Intelligence, Domain Analysis & Security Audits [P0]

**Goal:** Execute the **6 fixed URL checks** (`gsb`, `urlhaus`, `domain`, `tls`, `ct`, `headers`).

```
URL Checks (6 Fixed IDs for Coverage):
├── [gsb]      Google Safe Browsing v4 Lookup
├── [urlhaus]  URLhaus malware/phishing database query
├── [domain]   Punycode, typosquatting, brand subdomains, RDAP age
├── [tls]      TLS socket handshake to validated IP + distrust list
├── [ct]       Certificate Transparency entries via crt.sh (8s timeout)
└── [headers]  HTTP security headers & cookie flag inspection
```

#### 1. Threat Intelligence Connectors
- **Google Safe Browsing (`gsbClient.js`):**
  - Check ID: `gsb`. Name: `"Google Safe Browsing"`.
  - Check for `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`.
  - If match $\rightarrow$ check status `match_found`, severity `critical`, category `confirmed`.
  - If no match $\rightarrow$ check status `no_match`.
  - If unconfigured/error $\rightarrow$ `unavailable` or `error` (does not count toward coverage).
- **URLhaus (`urlhausClient.js`):**
  - Check ID: `urlhaus`. Name: `"URLhaus"`.
  - Query `https://urlhaus-api.abuse.ch/v1/url/`.
  - Result: `match_found` (if listed), `no_match` (clean), `unavailable` (on timeout/network error).

#### 2. Domain & Homoglyph Analyzer (`src/services/domainAnalyzer.js`)
- Check ID: `domain`. Name: `"Domain and brand analysis"`.
- **Punycode / Homoglyph Detection:** Detect IDN homoglyphs (e.g. Cyrillic `а` in `pаypal.com`).
- **Typosquatting Engine:** Test target domain against high-profile target brands (e.g. PayPal, Apple, Microsoft, Amazon, Google, Netflix, major banks):
  - Check Levenshtein distance = 1.
  - Check character substitutions (e.g. `l` $\rightarrow$ `1`, `o` $\rightarrow$ `0`).
- **Brand-in-Subdomain Detection:** Flag domains where brand names appear as subdomains (e.g. `paypal.com.verify-security.example`).
- **RDAP Domain Age & Registrar Query:** Query `https://rdap.org/domain/<domain>`:
  - Extract domain creation date. If domain was registered within 30 days, generate a `medium` severity heuristic finding.
  - Extract registrar name for contextual evidence.

#### 3. TLS Inspector with Distrust List & Weak Crypto (`src/services/tlsInspector.js`)
- Check ID: `tls`. Name: `"TLS inspection"`.
- **Direct Connection to Validated IP:** Connect socket to `validatedIp:443` while passing `{ servername: hostname }`.
- **Distrusted CAs Check:**
  - Maintain list of known compromised or distrusted CAs (e.g., WoSign, StartCom, DigiNotar).
  - Add `tls.distrust = { status: "no_match" | "match_found" | "not_checked", source: "Distrusted CA catalog", note: "..." }`.
  - If match found, set `tls.status = "untrusted_chain"`.
- **Weak Crypto Check:**
  - Check cipher suite and key size: RSA $< 2048$ bits, EC $< 256$ bits, or legacy algorithms (SHA-1, MD5, RC4, 3DES).
  - If weak crypto detected, set `tls.status = "weak_crypto"`, and emit finding with severity `high`.
- **Certificate Fields:** Extract `valid`, `validFrom`, `validTo`, `daysRemaining`, `issuer`, `subject`, `san`, `hostnameMatch`, `publicKey`, `signatureAlgorithm`, `chainTrusted`, `chain`.
- **Rule:** Never claim to detect CA key-generation flaws from a URL.

#### 4. Certificate Transparency Client (`src/services/ctService.js`)
- Check ID: `ct`. Name: `"Certificate Transparency"`. Source: `"crt.sh"`.
- Query `https://crt.sh/?q=<domain>&output=json` with strict 8-second timeout (`AbortController`).
- On timeout/upstream failure, set status `error` or `unavailable` with note: *"Provider timed out after 8s. Not treated as a clean result."*
- If entries found, record count in `ct.entries`.

#### 5. HTTP Security Headers Inspector (`src/services/safeHttpClient.js`)
- Check ID: `headers`. Name: `"HTTP security headers"`.
- Audit `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`.
- Audit cookie flags (`Secure`, `HttpOnly`, `SameSite`).
- Report missing headers as category `weakness`, severity `low`.

---

### Phase 4: Phishing Language Analysis Engine (Message Flow) [P1]

**Goal:** Execute the **4 fixed message checks** (`indicators`, `tactics`, `threat_intel`, `links`) on submitted messages.

```
Message Checks (4 Fixed IDs for Coverage):
├── [indicators]   Extraction of URLs, domains, emails, and phone numbers
├── [tactics]      Detection of psychological pressure & phishing tactics
├── [threat_intel] Threat intelligence lookup on extracted URLs (GSB & URLhaus)
└── [links]        Brand-to-domain consistency check (claimed brand vs link host)
```

#### 1. Indicator Extractor (`indicators`)
- Parse input for URLs, domain names, phone numbers, and emails.
- Store under `message.indicators`.

#### 2. Phishing Tactics & Non-Overlapping Highlighter (`tactics`)
- Map occurrences of: `urgency`, `threat`, `impersonation`, `fake_reward`, `account_suspension`, `otp_request`, `password_request`, `payment_request`, `suspicious_link`, `social_engineering`.
- Calculate character offsets `{ start, end, phrase, tactic }` relative to the **original submitted text**.
- Remove overlapping highlight spans (preserve the longest/highest severity match).

#### 3. Extracted Links & TI Lookups (`threat_intel` & `links`)
- Query Google Safe Browsing and URLhaus for all extracted URLs.
- Cross-reference claimed brand with the link destination host (e.g. text mentions "SBI" but link points to `sbi-kyc-update.example`). Emit finding category `heuristic`, severity `high`.

---

### Phase 5: Risk Scoring Arbiter & AI Narrative Engine [P0]

**Goal:** Calculate coverage, evaluate heuristic scores, determine classification independently of the LLM, and synthesize plain-English summaries safely.

#### 1. Coverage Calculation & Scoring Rules
- **Coverage Rule:** `coverage.completed` = count of checks where status $\in \{$ `completed`, `no_match`, `match_found` $\}$. Checks with `unavailable`, `error`, `not_checked` do not count. Total = 6 (for URLs) or 4 (for messages).
- **Classification Arbiter (The LLM NEVER sets the classification):**
  1. `confirmed_malicious`: At least one check has status `match_found`.
  2. `high_risk`: Heuristic score $\ge 70$, or critical message tactic combination (e.g. OTP request + bank impersonation + domain mismatch).
  3. `suspicious`: Heuristic score between 40 and 69 (e.g. typosquatting, HTTP on sign-in path, missing certificates).
  4. `low_risk`: All checks clean, heuristic score $< 40$.
  5. `inconclusive`: When `coverage.completed < (coverage.total / 2)` and no confirmed match found.

#### 2. AI Narrative Generation Rules (`src/services/aiExplainer.js`)
- **Sanitized Input Only:** The LLM receives **only structured evidence** (finding titles, check statuses, domain facts). It **never** receives raw page HTML or raw executable scripts.
- **Message Data Privacy:** Send only redacted or derived indicator data to external AI services, **never the full raw message**.
- **Untrusted Content Handling:** The system prompt instructs the model that all submitted user text is untrusted.
- **Strict Output Validation:** The LLM output is validated against a Zod schema (`summary`, `keyPoints`, `recommendations`, `limitations`).
- **Template Fallback:** If the LLM call times out (5s), returns invalid JSON, or encounters an error, the deterministic template fallback automatically generates the narrative, setting `explanation.source = "template"`.

---

### Phase 6: Async Worker & Polling Lifecycle [P0]

**Goal:** Implement `POST /api/investigations` (202 Accepted) and `GET /api/investigations/:id` (polling every 1.2s) backed by the in-memory repository.

#### 1. In-Memory Stepper Progression
Steps executed in sequence, updating repository state:
1. `submission`: Mark `completed`.
2. `investigation`: Target structure & indicator extraction. Mark `running` $\rightarrow$ `completed`.
3. `threat_intel`: GSB & URLhaus lookups. Mark `running` $\rightarrow$ `completed`.
4. `tls_security`: TLS handshake, crt.sh & headers check. Mark `running` $\rightarrow$ `completed`.
5. `risk_report`: Heuristic scoring & AI explanation. Mark `running` $\rightarrow$ `completed`.
- If an uncaught error occurs, set `status = "failed"`, record `error: { message }`, set the active step to `failed`, and set remaining steps to `skipped`.

#### 2. Endpoints Implementation
- **`POST /api/investigations`**
  - Rate-limited: max 30 per 10 minutes per IP.
  - Accepts `{ type: "url", target }` or `{ type: "message", content }`.
  - Generates ID `INV-YYYYMMDD-<16_HEX_CHARS>`.
  - Saves initial record in `repository` with all steps initialized.
  - Triggers async background worker process.
  - Returns HTTP `202 Accepted`:
    ```json
    { "success": true, "investigationId": "INV-20261107-7f3a2c9d1e4b8a5f", "status": "processing" }
    ```
- **`GET /api/investigations/:id`**
  - Fetches record from `repository`. Returns `404 NOT_FOUND` if missing.
  - While `processing`: returns steps and preliminary checks array so the UI stepper renders live.
  - Once `completed`: returns full report conforming to the API contract.

---

### Phase 7: Community Threat Reports Engine [P1]

**Goal:** Enable anonymous submissions with rate limiting, community voting, report listing, and on-chain registration capability.

#### 1. Endpoints Implementation
- **`POST /api/community/reports`**
  - Rate-limited: max 10 per 15 minutes per IP.
  - Anonymous submissions allowed (optional session check).
  - Payload: `{ targetType, target, category, description }`.
  - Validate: `targetType` (`url`, `domain`, `phone`, `email`), description 20–1000 characters, category enum.
  - Store in `repository` with `status: "pending_review"`, `validation: { confirms: 0, disputes: 0 }`.
  - Return HTTP `201`:
    ```json
    { "success": true, "report": { "id": "CR-20261107-a91b3c4d5e6f7a8b", "status": "pending_review" } }
    ```
- **`GET /api/community/reports`**
  - Return all community reports from `repository` with sanitized `targetDisplay`.
- **`POST /api/community/reports/:id/vote`**
  - Payload: `{ voteType: "confirm" | "dispute" }`.
  - Increments `confirms` or `disputes` counter in `repository`.
  - Returns updated validation state.
- **On-Chain Community Registration:**
  - Support anchoring validated community reports to the smart contract via `POST /api/registry/register` (passing `communityReportId`).

---

### Phase 8: Hardhat Smart Contracts & Sepolia Integrity Engine [P0]

**Goal:** Build a separate `contracts/` Hardhat project, deploy to a local node first, and integrate Ethers.js for canonical report hashing and on-chain verification.

#### 1. Hardhat Contracts Project (`contracts/`)
Create a standalone Hardhat project in `contracts/`:
- **`contracts/CyberlensRegistry.sol`:**
  ```solidity
  // SPDX-License-Identifier: MIT
  pragma solidity ^0.8.20;

  contract CyberlensRegistry {
      enum ReportStatus { Registered, Validated, Disputed }

      struct Record {
          bytes32 reportHash;
          uint256 timestamp;
          uint256 blockNumber;
          uint256 revision;
          ReportStatus status;
          address reporter;
      }

      mapping(string => Record) private _recordsById;
      mapping(bytes32 => string) private _idByHash;

      event ReportRegistered(string indexed investigationId, bytes32 indexed reportHash, uint256 revision);
      event ReportStatusUpdated(string indexed investigationId, ReportStatus status);

      function registerReport(string calldata investigationId, bytes32 reportHash) external {
          require(reportHash != bytes32(0), "Invalid hash");
          Record storage rec = _recordsById[investigationId];
          if (rec.timestamp != 0) {
              require(rec.reportHash == reportHash, "Hash mismatch on revision");
              return; // Idempotent: return without error if already registered
          }
          rec.reportHash = reportHash;
          rec.timestamp = block.timestamp;
          rec.blockNumber = block.number;
          rec.revision = 1;
          rec.status = ReportStatus.Registered;
          rec.reporter = msg.sender;
          _idByHash[reportHash] = investigationId;
          emit ReportRegistered(investigationId, reportHash, 1);
      }

      function getRecord(string calldata investigationId) external view returns (Record memory) {
          return _recordsById[investigationId];
      }

      function getRecordByHash(bytes32 reportHash) external view returns (Record memory) {
          string memory id = _idByHash[reportHash];
          require(bytes(id).length > 0, "Not found");
          return _recordsById[id];
      }

      function updateStatus(string calldata investigationId, ReportStatus newStatus) external {
          Record storage rec = _recordsById[investigationId];
          require(rec.timestamp != 0, "Not found");
          rec.status = newStatus;
          emit ReportStatusUpdated(investigationId, newStatus);
      }
  }
  ```
- **Automated Hardhat Tests (`contracts/test/CyberlensRegistry.test.js`):**
  - Test registration, idempotent re-registration, hash collision prevention, revision tracking, status transitions, and lookups by both ID and hash.
- **Local Testing:** Test on `npx hardhat node` before deploying to Sepolia testnet.

#### 2. Canonical Snapshot Serializer & Hasher (`src/services/canonicalHasher.js`)
- Exclude `demo`, `steps`, `status`, `registry`, polling fields, and raw message text.
- Sort keys lexicographically recursively.
- Canonical version prefix: `"cyberlens-report/v1"`.
- Compute SHA-256 hash:
  ```javascript
  const canonicalString = JSON.stringify(sortKeys(canonicalSnapshot));
  const reportHash = crypto.createHash('sha256').update(canonicalString).digest('hex');
  ```
- **Store the exact snapshot string** in `repository.storeCanonicalSnapshot(id, canonicalString)` so that future verifications compute against the exact byte-level snapshot.

#### 3. Registry Endpoints Implementation
- **`POST /api/registry/register`**
  - Request: `{ "investigationId": "INV-..." }` (frontend timeout: 90s).
  - **Idempotency:** If `repository.getRegistryEntryByInvestigationId(id)` already exists, return the existing mined receipt immediately without re-submitting a transaction.
  - Retrieve report, build canonical snapshot, compute SHA-256.
  - Submit transaction to Sepolia contract via Ethers.js. Wait for **1 mined block receipt**.
  - Save entry to `repository`.
  - Return HTTP `200` with status `"registered"`, `reportHash`, `txHash`, `blockNumber`, `explorerUrl`.
- **`POST /api/registry/verify`**
  - Accepts `{ investigationId }` or `{ reportHash }`.
  - Query smart contract. Compare on-chain hash against computed canonical hash.
  - Return `{ success: true, result: { integrity: "match" | "mismatch" | "not_registered", computedHash, onChainHash, ... } }`.
- **`GET /api/registry` (Threat Feed)**
  - Return array of registered items for `/threat-feed`.
  - Includes: `investigationId`, `classification`, `registeredAt`, `txStatus: "confirmed"`, `txHash`, `explorerUrl`, `network`, `category`, `providers`, `intelMatches`.
  - **CRITICAL:** Never expose raw URLs or message texts in this public feed.

---

### Phase 1: Authentication & Health Diagnostics [P1 - Build Auth Last]

**Goal:** Implement cookie-based authentication and service health diagnostics, built last as per project priorities.

#### 1. In-Memory User & Session Store
- Stored directly in `repository.users` and `repository.sessions`.
- Passwords hashed with `argon2.hash(password)`.

#### 2. Auth Endpoints
- **`POST /api/auth/register`:** Validate email, hash password, store user in repository.
- **`POST /api/auth/login`:** Rate-limited (max 5 attempts per 15 min). Verify password, create session in repository, set `httpOnly`, `Secure`, `SameSite=Lax` cookie.
- **`POST /api/auth/logout`:** Invalidate session in repository, clear cookie.
- **`GET /api/auth/me`:** Return current session user or `401`. Never return password hashes.

#### 3. Health Diagnostics (`GET /api/health`)
- Ping external dependencies: Google Safe Browsing, URLhaus, crt.sh, AI service, Sepolia RPC.
- Return status `"ok"` or `"degraded"`. Never leak API keys or private RPC URLs.

---

### Phase 9: Testing, Verification & Production Hardening [P0]

**Goal:** Validate all components against `docs/api-contract.md` and ensure environment safety.

#### 1. Integration Test Matrix
- [ ] Verify `POST /api/investigations` rate limiter triggers after 30 requests.
- [ ] Verify SSRF blocks `http://127.0.0.1`, `http://169.254.169.254`, `http://[::1]`, and hex/decimal encodings.
- [ ] Verify DNS resolves once and connects to the pinned IP directly.
- [ ] Verify fixed check IDs: 6 for URL (`gsb`, `urlhaus`, `domain`, `tls`, `ct`, `headers`), 4 for message.
- [ ] Verify `coverage.completed` ignores `unavailable`, `error`, and `not_checked`.
- [ ] Verify message highlighter start/end offsets match original text without collisions.
- [ ] Verify LLM failure defaults safely to template fallback without changing the classification.
- [ ] Verify `registerReport` is idempotent.
- [ ] Verify no database files, SQLite binaries, or Prisma artifacts exist in the repository.

#### 2. Environment Configuration Guide (`.env.example`)
```ini
# Server
PORT=4000
NODE_ENV=development
FRONTEND_URL=http://localhost:5173

# Session Security
SESSION_SECRET="super-secret-cryptographic-salt"

# Threat Intelligence API Keys
GOOGLE_SAFE_BROWSING_API_KEY=""
URLHAUS_API_KEY=""

# AI Engine
GEMINI_API_KEY=""

# Blockchain / Web3 (Sepolia Testnet - Use throwaway wallet only)
SEPOLIA_RPC_URL="https://sepolia.infura.io/v3/YOUR_INFURA_KEY"
REGISTRY_CONTRACT_ADDRESS="0x..."
REGISTRY_SIGNER_PRIVATE_KEY="0x..."
```

---

## 4. Phase Delivery Timeline & Prioritization Matrix

As established by the Architecture Amendments, phases are prioritized to deliver the core security intelligence and blockchain pipelines first, deferring authentication to the final stage:

| Phase | Milestone | Priority | Focus |
|---|---|---|---|
| **Phase 0** | Setup, Project Layout & In-Memory Repository | **P0** | In-memory store, response helpers, ID generator |
| **Phase 2** | SSRF Shield, DNS Pinning & Safe Client | **P0** | Single-resolve, CIDR checks, alternate encoding blocks |
| **Phase 3** | Threat Intel, Domain & Security Audits | **P0** | 6 fixed URL checks, punycode/typosquatting, TLS distrust |
| **Phase 5** | Scoring Arbiter & AI Narrative Engine | **P0** | 0–100 heuristic scoring, LLM independence, templates |
| **Phase 6** | Async Queue & Polling Lifecycle | **P0** | Stepper state updates, 202 Accepted, 1.2s polling |
| **Phase 8** | Hardhat Contracts & Sepolia Integrity | **P0** | Hardhat project, canonical hashing, on-chain registry |
| **Phase 9** | Testing & Hardening | **P0** | Contract compliance, SSRF tests, coverage verification |
| **Phase 4** | Phishing Engine & Message Highlighter | **P1** | 4 fixed message checks, non-overlapping offsets |
| **Phase 7** | Community Threat Reports | **P1** | Anonymous submission, voting, community registry |
| **Phase 1** | Authentication & Health Diagnostics | **P1 (Build Last)** | Sessions, cookies, Argon2, health pingers |

---

## 5. Verification Checklist for Member 2

Before declaring the backend ready for frontend integration without mocks:
1. [ ] No Prisma or SQLite dependencies installed; all state operates via `src/store/repository.js`.
2. [ ] Rate limiting is enforced on `POST /api/investigations` and `POST /api/auth/login`.
3. [ ] DNS resolution occurs once; connections bind to the pre-validated IP directly.
4. [ ] Fixed check IDs match the contract (6 for URL, 4 for message).
5. [ ] The LLM does not set classifications and only receives sanitized evidence.
6. [ ] Canonical report snapshot is stored and verified with SHA-256 on the Hardhat contract.
7. [ ] Threat Feed (`GET /api/registry`) contains zero raw URLs or sensitive message contents.
