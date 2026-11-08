# CYBERLENS Backend Service

AI-powered threat detection and digital trust platform API server.

## Architectural Notes (Amendment 1 Compliance)
- **Zero Database / Pure In-Memory Repository:** Uses `src/store/repository.js`. There is **no Prisma, no SQLite, and no `prisma/` folder**. Routes and services interact only with the repository interface.
- **Base Path:** `/api` on port `4000` (proxied by Vite frontend dev server at `http://localhost:5173/api`).
- **Standard Envelopes:** Strict compliance with `docs/api-contract.md`.

## Setup & Running

```bash
cd backend
npm install
cp .env.example .env   # then fill in (see docs/SETUP.md)
npm run dev
```

Server listens on `http://localhost:4000`. **Full run guide (blockchain + backend + website): [docs/SETUP.md](docs/SETUP.md).**
API additions: [docs/API.md](docs/API.md). Merge notes for the team: [docs/HANDOVER.md](docs/HANDOVER.md).

| Phase | Status |
|---|---|
| 0 Setup & repository | ✅ |
| 1 Authentication & health | ✅ Argon2id, sessions in the repository, CSRF, RBAC, live/ready probes |
| 2 SSRF shield | ✅ |
| 3 Threat intel & audits | ✅ |
| 4 Message phishing engine | ✅ 4 checks, non-overlapping highlights |
| 5 Scoring & AI narrative | ✅ |
| 6 Async queue | ✅ |
| 7 Community reports | ✅ validation, masking, one-vote-per-voter, admin moderation |
| 8 Contracts & on-chain integrity | ✅ Hardhat project in `../contracts`, real register/verify |
| 9 Testing & hardening | ✅ 173 backend tests + 12 contract tests |

## Phase 2: SSRF Shield & Safe Network Client Guarantees
- **Target URL Validation:** Strictly allows `http:` and `https:` protocols, length $\le 2048$, ports `80` and `443` only (all other explicit ports rejected), rejects embedded credentials (`user:pass@`), and rejects empty hostnames.
- **Encoding & Alternate Notation Protection:** Blocks numeric hostnames (e.g. `http://2130706433/`), hex-encoded parts (e.g. `http://0x7f.0.0.1/`), and octal notation (e.g. `http://0177.0.0.1/`).
- **Comprehensive CIDR Blacklist (`net.BlockList`):** Blocks all private (RFC 1918), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), carrier-grade NAT, test/benchmark nets, multicast, reserved ranges, IPv6 `::`, `::1`, `fc00::/7`, `fe80::/10`, `64:ff9b::/96`, and IPv4-mapped IPv6 `::ffff:0:0/96` (extracting and validating embedded IPv4).
- **DNS Pinning:** Resolves target DNS exactly **once** per hop. Connects to the validated IP through the HTTP/HTTPS agent's custom lookup (supporting `options.all === true` and `autoSelectFamily: false`), preserving the original hostname for the `Host` header and TLS SNI (`servername`). Hostnames are never re-resolved, preventing DNS rebinding.
- **Safe Redirect Follower:** Enforces ports 80/443 and full SSRF re-validation on every redirect hop (`301`, `302`, `303`, `307`, `308`), caps redirects at 5 hops, detects redirect loops, and flags hops as suspicious when registrable domains change or protocols downgrade.
- **Query Parameter Redaction:** Automatically scrubs sensitive query parameters (`token`, `session`, `auth`, `key`, `password`, `code`, `sig`, `signature`, `secret`, `apikey`) to `[redacted]` across redirect chains, logs, and errors.
- **Data & Resource Limits:** Enforces a maximum response size (1MB) and timeout (8s), aborting cleanly and keeping only small body snippets. Never sends cookies or auth headers. Fixed User-Agent `CyberLens-Scanner/1.0`.

## Phase 3: Threat Intelligence, Domain Analysis & TLS Inspection
- **6 Fixed URL Checks:** `gsb`, `urlhaus`, `domain`, `tls`, `ct`, `headers`.
- **Threat Intel Integrations:** Google Safe Browsing Lookup v4 and abuse.ch URLhaus query clients with sanitized query parameters.
- **Domain Analysis:** Punycode/homoglyph detection, typosquatting check (Levenshtein distance & digit substitutions), brand-in-subdomain detection, and RDAP registration age lookup.
- **TLS Inspection & Distrusted CA Catalog:** Direct socket TLS handshake to validated IP checking validity, hostname mismatch, cryptographic strength, and curated distrusted root/intermediate CAs.
- **Certificate Transparency:** Querying crt.sh logs with timeout isolation.

## Phase 5: Risk Scoring Arbiter & AI Narrative Engine
- **Coverage Engine (`coverage.js`):** Counts only completed checks (`completed`, `no_match`, `match_found`). Missing, error, unavailable, or not_checked checks do not count towards completed coverage.
- **Deterministic Heuristic Scoring (`heuristicEngine.js`):** Sums finding weights capped at 100 with a 10-point cap on header findings. The LLM never sets scores.
- **Risk Classification Arbiter:** Evaluated in strict order: (1) `confirmed_malicious` (ONLY via GSB or URLhaus `match_found`), (2) `high_risk` ($\ge 70$), (3) `inconclusive` (coverage $< \text{total}/2$), (4) `suspicious` (40–69), (5) `low_risk` ($< 40$).
- **Confidence Rating:** Evaluates to `high` only when coverage is complete, all threat intel checks completed, and no contradictions exist. Evaluates to `medium` for partial coverage ($\ge \text{total}/2$) or when threat intel is unavailable. Evaluates to `low` when coverage $< \text{total}/2$.
- **AI Narrative Explainer (`aiExplainer.js`):**
  - **Sanitized Allowlist Input:** Receives only classification, score, confidence, coverage, sanitized hostname, and minimal finding metadata (`id`, `title`, `severity`, `category`, `checkId`).
  - **Strict Content Exclusions:** Never receives raw page HTML, cookies, header values, cert subject text, or redirect query strings.
  - **Prompt Injection Defense & Contradiction Guard:** Instructs model that all input is untrusted. If AI output mentions a classification term that contradicts the deterministic decision, it is automatically discarded and replaced with the deterministic template fallback.
  - **Schema Validation & Fallback:** Validates structured JSON output using Zod (`summary`, `keyPoints`, `recommendations`, `limitations`). Automatically reverts to `template` fallback on timeout (5s), missing API key, network error, or schema violation.
- **Report Builder (`reportBuilder.js`):** Orchestrates coverage, scoring, classification, confidence, and narrative generation into a complete contract-compliant report.

## Testing

Run all unit and integration tests:

```bash
npm test
```

Tests run completely offline with no real internet calls required. In-memory resolvers, local HTTP test servers, and mock fetch injectors verify Phases 0–7. Phase 8 tests start a real local Hardhat node (port 8547) from `../contracts` (run `npm install` there first; otherwise they are skipped).

## Directory Structure

```
backend/
├── src/
│   ├── app.js                   # Express application assembly
│   ├── server.js                # Port 4000 listener
│   ├── config/
│   │   ├── env.js               # Validated environment configuration
│   │   └── constants.js         # Shared enums, check IDs, error codes
│   ├── data/
│   │   ├── distrustedCAs.json   # Curated, cited catalog of distrusted CAs
│   │   └── TODO_distrusted_cas.md # Excluded CAs pending verification
│   ├── store/
│   │   └── repository.js        # In-Memory Repository
│   ├── middleware/
│   │   ├── auth.js              # requireAuth / requireRole / loadAuth (Phase 1)
│   │   ├── csrf.js              # CSRF token + origin check (Phase 1)
│   │   ├── session.js           # express-session, hardened cookie (Phase 1)
│   │   ├── errorHandler.js      # Contract error envelope formatter
│   │   ├── rateLimiter.js       # Rate limiters (investigations, login, community)
│   │   └── validate.js          # Zod schema validation middleware
│   ├── controllers/
│   │   ├── healthController.js
│   │   ├── investigationController.js
│   │   ├── registryController.js
│   │   ├── communityController.js
│   │   └── authController.js
│   ├── routes/
│   │   ├── healthRoutes.js
│   │   ├── investigationRoutes.js
│   │   ├── registryRoutes.js
│   │   ├── communityRoutes.js
│   │   └── authRoutes.js
│   ├── services/
│   │   ├── auth/                # passwordHasher, sessionStore, authService, authValidation (Phase 1)
│   │   ├── messageAnalyzer.js   # Phase 4 message checks & highlighter
│   │   ├── canonicalHasher.js   # Phase 8 canonical snapshot + SHA-256
│   │   ├── blockchainService.js # Phase 8 ethers bridge (local / Sepolia)
│   │   ├── coverage.js          # Check coverage calculator
│   │   ├── heuristicEngine.js   # Deterministic scoring, classification, and confidence
│   │   ├── aiExplainer.js       # Gemini narrative generator & template fallback
│   │   ├── reportBuilder.js     # Contract report assembler
│   │   ├── urlChecks.js         # Parallel 6-check orchestrator
│   │   ├── domainAnalyzer.js    # Typosquatting, Punycode & RDAP inspection
│   │   ├── tlsInspector.js      # TLS certificate & distrusted CA inspection
│   │   ├── ctService.js         # Certificate Transparency checker
│   │   ├── headersInspector.js  # Security headers & cookie audit
│   │   ├── ssrfValidator.js     # SSRF validation, CIDR blocking & resolver
│   │   ├── safeHttpClient.js    # Pinned safe HTTP client with redirect tracking
│   │   └── threatIntel/
│   │       ├── gsbClient.js     # Google Safe Browsing Lookup v4
│   │       └── urlhausClient.js # URLhaus threat query client
│   └── utils/
│       ├── idGenerator.js       # 16-hex secure ID generator
│       ├── logger.js            # Secret-redacting logger
│       └── response.js          # Standard success/error helpers
├── test/
│   ├── health.test.js           # Provider reachability & caching tests
│   ├── phase0.test.js           # Core architecture & repository tests
│   ├── phase2_ssrf.test.js      # SSRF, DNS pinning, redirect & limit tests
│   ├── phase3_url_checks.test.js # Phase 3 url checks & distrusted CA tests
│   └── phase5_scoring_ai.test.js # Phase 5 coverage, scoring, classification, and AI tests
├── docs/                        # SETUP.md, API.md, HANDOVER.md
├── .env.example
└── package.json
```

