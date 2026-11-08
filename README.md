# CYBERLENS contracts

Hardhat project for `CyberlensRegistry`, the on-chain integrity registry for CYBERLENS reports. Only hashes and report IDs go on-chain.

```bash
npm install
npm test               # 12 contract tests (in-process Hardhat network)
npm run node           # local chain on http://127.0.0.1:8545 (keep it running)
npm run deploy:local   # deploy to the local chain; prints the backend/.env lines
npm run deploy:sepolia # needs contracts/.env (see .env.example) — throwaway wallet only
```

- The compiler is the bundled `solc` npm package (0.8.24), so compiling works offline.
- Contract rules:
  - registration is idempotent;
  - a hash can't be reused for a different ID;
  - `reviseReport` increases the revision;
  - `updateStatus` is owner-only;
  - only registrars (the backend signer) can write.
- Full setup: `../backend/docs/SETUP.md`.
