# CYBERLENS — Frontend

React 18 + Vite + Tailwind CSS + React Router + Framer Motion. Responsive website only.

## Run

```bash
cd frontend
npm install

npm run dev        # talks to the backend at http://localhost:4000 via /api proxy
npm run dev:demo   # no backend needed — uses clearly labelled DEMO FIXTURES
npm run build      # production build → dist/
```

Open http://localhost:5173.

## Demo mode vs live mode

| | `npm run dev:demo` | `npm run dev` |
|---|---|---|
| Data source | `src/services/mock/fixtures.js` | Express backend |
| Labelling | Yellow "DEMO MODE" bar + "Demo fixture" banner on every report | none |
| Arbitrary input | Returns **Inconclusive** with all checks "Unavailable" | Real investigation |
| Blockchain | Register / Verify **refuse** (no fake tx hashes) | Real testnet transactions |
| Login / Register / Community submit | **Refuse** with a clear message (nothing faked) | Backend `/api/auth/*`, `/api/community/*` |
| Data persistence | In memory — gone on reload | Database |

Demo fixtures exist so the UI can be built and rehearsed before the backend is ready. They must never be presented as live threat intelligence.

## Pages

Navbar: **Logo | Home | Scanner | Threat Feed | Community | Verify | Login | Register | Scan Now →**

| Route | Page |
|---|---|
| `/` | Home: hero, Welcome to CYBERLENS (about), How It Works, Intelligence Engines, Methodology, Digital Trust & Blockchain, final CTA |
| `/scanner` | Live investigation console (URL / domain + message). "Scan Now" opens it and focuses the input |
| `/threat-feed` | Registered investigations + community reports, filter by source / classification / status |
| `/community` | Submit a threat report; list of community reports (always marked unverified) |
| `/verify` | Report ID or hash → SHA-256 integrity comparison (`?id=` prefill supported) |
| `/login`, `/register` | Account pages; talk to `/api/auth/*` (see `docs/api-contract.md`) |
| `/report/:id` | Investigation report (polls while processing) |
| `/registry` | Redirects to `/threat-feed` |

## Structure

```
src/
  pages/              HomePage, ScannerPage, ThreatFeedPage, CommunityPage, VerifyPage,
                      LoginPage, RegisterPage, ReportPage, NotFoundPage
  layouts/            AppLayout (page transitions), AnimatedBackground (light, grid, streaks,
                      particle canvas), GlassNavbar, Footer
  components/         HeroSection, RadarScanner, PlatformIntro, WorkflowTimeline,
                      IntelligenceSection, MethodologySection, BlockchainVisualization, FinalCTA,
                      InvestigationConsole, CertificateVisualization, MessageAnalysisPreview, AuthShell
    ui/               Glass (GlassPanel, GlassButton, Reveal, SectionHeading, ExampleLabel),
                      Badges, Tooltip, States, Logo
    report/           ProgressStepper, ReportHeader, ExplanationPanel, EvidenceSection,
                      RedirectChain, TlsSection, SecurityHeaders, MessageAnalysis,
                      RegistryPanel, SidePanels
  hooks/              useInvestigation (fetch + poll), useAuth (AuthProvider), useScanNow
  services/           api.js (single API client), mock/ (fixtures + mock API)
  utils/              constants, url, format, tones (brand-mapped), session
```

## Design system

Brand palette (only these, plus amber/orange/red for risk states):

| Token | Hex | Use |
|---|---|---|
| Cyan Pulse (`signal`, `--cyan-pulse`) | `#00D1B2` | accents, buttons, active states, glows, Low Risk |
| Midnight Grid (`midnight`, `ink-*` scale) | `#001F3F` | backgrounds, deep surfaces |
| Pure Signal (`white`) | `#FFFFFF` | headings, key text, technical info |
| Carbon Core (`carbon`) | `#2E2E2E` | glass tint, muted/unavailable states |

Glass utilities live in `src/index.css`: `.glass`, `.glass-strong`, `.glass-hover`, `.edge-glow`, `.panel`.
All animation respects `prefers-reduced-motion`. Homepage showcase sections are marked **Illustrative example — not a live scan**.

## Contract

The frontend is built to `../docs/api-contract.md`. If the backend changes a shape, update that doc **and** the fixtures together.

## Security notes

- Only `VITE_*` variables reach the browser. Never put API keys or wallet keys in frontend env files.
- Client-side URL validation is for UX only; the backend must enforce SSRF protection.
- Submitted message text is kept only in this tab's `sessionStorage` for phrase highlighting.
- Nothing from a report is rendered as HTML (no `dangerouslySetInnerHTML`), so report content cannot inject script.
