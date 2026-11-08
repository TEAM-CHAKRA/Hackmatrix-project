# CYBERLENS — Run the whole project

**Quickest way:** from the project folder run `bash start-cyberlens.sh` — it installs, starts the blockchain, deploys the contract, fills in `backend/.env` and starts backend + website. Press Ctrl+C to stop.

Or by hand — three parts, three terminals:

| Terminal | Folder | Command | What it is |
|---|---|---|---|
| 1 | `contracts/` | `npm run node` | Local blockchain (Hardhat), port 8545 |
| 2 | `backend/` | `npm run dev` | API server, port 4000 |
| 3 | `frontend/` | `npm run dev` | Website, http://localhost:5173 |

Requires **Node.js 20.12+** (tested on 22 and 24). Stop servers with **Ctrl+C**, not Ctrl+Z: Ctrl+Z only pauses them and keeps the port busy.

---

## 1. One-time install

```bash
cd ~/Desktop/Hackmatrix-project/contracts && npm install
cd ../backend && npm install
cd ../frontend && npm install
```

## 2. Start the local blockchain (terminal 1)

```bash
cd ~/Desktop/Hackmatrix-project/contracts
npm run node
```

This prints 20 test accounts. Copy the **Private Key of Account #0**. It is a public Hardhat test key: never send real funds to it.

Leave this terminal running.

## 3. Deploy the registry contract (new terminal, once per blockchain start)

```bash
cd ~/Desktop/Hackmatrix-project/contracts
npm run deploy:local
```

The script prints the lines for `backend/.env`, for example:

```
CHAIN_MODE=local
REGISTRY_CONTRACT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3
LOCAL_RPC_URL=http://127.0.0.1:8545
```

> The local chain is wiped every time `npm run node` restarts, so you must deploy again after each restart. The address is usually the same.

## 4. Configure the backend

```bash
cd ~/Desktop/Hackmatrix-project/backend
cp .env.example .env
```

Edit `backend/.env`:

```ini
SESSION_SECRET=<run: node -e "console.log(require('crypto').randomBytes(48).toString('hex'))">
CHAIN_MODE=local
REGISTRY_CONTRACT_ADDRESS=<address from step 3>
REGISTRY_SIGNER_PRIVATE_KEY=<Account #0 private key from step 2>

# Optional, but needed to moderate community reports (validate / reject):
ADMIN_EMAIL=you@example.com
ADMIN_PASSWORD=<a strong password with letters and numbers>

# Optional: permanent storage in Supabase (see DATABASE.md). Empty = in-memory.
SUPABASE_URL=
SUPABASE_SERVICE_ROLE_KEY=

# Optional threat-intel / AI keys. Without them those checks show "unavailable", never "clean":
GOOGLE_SAFE_BROWSING_API_KEY=
URLHAUS_API_KEY=          # free Auth-Key from https://auth.abuse.ch/
GEMINI_API_KEY=
```

## 5. Start the backend (terminal 2)

```bash
npm run dev
```

You should see:

```
⛓️  Blockchain: Hardhat Local (contract 0x5FbD…)
🚀 CYBERLENS Backend listening on http://localhost:4000
```

To check it, open http://localhost:4000/api/health. You should see `blockchain: "ok"`. The status is `degraded` until the threat-intel API keys are set; that is expected and honest.

## 6. Start the website (terminal 3)

```bash
cd ~/Desktop/Hackmatrix-project/frontend
npm run dev            # live mode, talks to the backend
# npm run dev:demo     # demo mode, sample data only, no backend needed
```

Open http://localhost:5173.

## 7. Try everything

1. **Scanner → Message**: paste a fake SBI/OTP SMS and press Analyze Message. You get a High Risk report with highlighted phrases.
2. **Scanner → Link**: paste any website. You get a full report covering domain, TLS, headers, CT and threat intel.
3. On a finished report, click **Register on-chain**. The report's fingerprint is mined on your local chain.
4. **Verify**: paste the report ID. The result is "Cryptographic Integrity Verified".
5. **Threat Feed**: registered reports appear here, without raw links.
6. **Community**: submit a report. To approve it, sign in as the admin and send `PATCH /api/community/reports/:id/status` (see API.md).
7. **Register / Login / Logout** in the navbar.

## 8. Run the tests

```bash
cd backend && npm test      # 179 tests: all phases, incl. a real local chain
cd backend && npm run db:check   # is Supabase connected and set up?
cd contracts && npm test    # 12 contract tests
```

The backend's Phase 8 tests start their own Hardhat node on port 8547. They need `contracts/` to be installed (`npm install` in `contracts/`); otherwise those tests are skipped.

---

## Deploying to Sepolia (optional, for the public demo)

1. Create a **new throwaway wallet** (for example a fresh MetaMask account) and get free Sepolia ETH from a faucet.
2. Get an RPC URL, for example from Infura or Alchemy (Sepolia).
3. Set up `contracts/.env`:
   ```ini
   SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/<key>
   DEPLOYER_PRIVATE_KEY=<throwaway wallet key>
   ```
4. Deploy:
   ```bash
   cd contracts && npm run deploy:sepolia
   ```
5. In `backend/.env`:
   - set `CHAIN_MODE=sepolia`;
   - set `SEPOLIA_RPC_URL`;
   - set `REGISTRY_CONTRACT_ADDRESS` to the new address;
   - set `REGISTRY_SIGNER_PRIVATE_KEY` to the same throwaway key.
6. Restart the backend. Reports now link to sepolia.etherscan.io.

## Production checklist

- Set `NODE_ENV=production`.
- Set `SESSION_SECRET` to at least 32 random characters. The published dev default is rejected.
- Set `FRONTEND_URL` to the real origin.
- Serve over HTTPS (secure cookies require it).
- Set `TRUST_PROXY` when behind a proxy.
- Use Supabase (`SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY`). Without it, set `ALLOW_MEMORY_SESSION_STORE=true` to accept in-memory storage.
- The server **refuses to start** if any of these are missing. It prints the variable names, never their values.

## Known limitations

- **Storage**: without Supabase settings, all data is in memory and resets when the backend restarts. With `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` set, everything is stored permanently in Supabase. See [DATABASE.md](DATABASE.md).
- **Message highlights**: the raw message is deleted after analysis (privacy). Highlights show in the tab where you ran the scan; a report opened later shows the findings but not the highlighted text.
- **URLhaus** requires a free Auth-Key. Without it, the URLhaus check reports "error" and does not count toward coverage.
- **Contracts tooling**: `npm audit` in `contracts/` reports issues in Hardhat's own build tools. They only run on your computer during development and are never part of the website.
