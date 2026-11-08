#!/usr/bin/env bash
# CYBERLENS — one-command local start (macOS / Linux).
#   bash start-cyberlens.sh
# Installs dependencies, starts a local blockchain, deploys the registry
# contract, configures backend/.env, then runs blockchain + backend + website.
# Press Ctrl+C in this window to stop everything.

set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
CONTRACTS="$ROOT/contracts"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
# Hardhat's public development key (Account #0). Local test chain ONLY.
DEV_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

say() { printf '\n\033[1;36m▶ %s\033[0m\n' "$1"; }
fail() { printf '\n\033[1;31m✖ %s\033[0m\n' "$1"; exit 1; }

command -v node >/dev/null || fail "Node.js is not installed (need 20.12+)."

free_port() {
  local pids
  pids=$(lsof -ti "tcp:$1" -sTCP:LISTEN 2>/dev/null || true)
  if [ -n "$pids" ]; then kill $pids 2>/dev/null || true; sleep 1; fi
}

wait_for() { # url, label, [log file]
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null "$1" 2>/dev/null; then return 0; fi
    sleep 1
  done
  if [ -n "${3:-}" ] && [ -f "$3" ]; then printf '\nLast lines of %s:\n' "$3"; tail -n 15 "$3"; fi
  fail "$2 did not start. See the log file mentioned above."
}

say "Stopping anything already running on ports 8545, 4000, 5173"
free_port 8545; free_port 4000; free_port 5173

say "Installing dependencies (first run takes a few minutes)"
(cd "$CONTRACTS" && npm install --no-audit --no-fund) || fail "npm install failed in contracts/"
(cd "$BACKEND" && npm install --no-audit --no-fund) || fail "npm install failed in backend/"
(cd "$FRONTEND" && npm install --no-audit --no-fund) || fail "npm install failed in frontend/"

say "Starting the local blockchain (log: contracts/hardhat-node.log)"
(cd "$CONTRACTS" && HARDHAT_DISABLE_TELEMETRY_PROMPT=true npx hardhat node > hardhat-node.log 2>&1) &
CHAIN_PID=$!
for _ in $(seq 1 60); do
  curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' http://127.0.0.1:8545 >/dev/null 2>&1 && break
  sleep 1
done

say "Deploying the CyberlensRegistry contract"
(cd "$CONTRACTS" && HARDHAT_DISABLE_TELEMETRY_PROMPT=true npx hardhat run scripts/deploy.js --network localhost) || fail "Contract deployment failed"
ADDRESS=$(node -e "console.log(require('$CONTRACTS/deployments/localhost.json').address)")

say "Configuring backend/.env"
[ -f "$BACKEND/.env" ] || cp "$BACKEND/.env.example" "$BACKEND/.env"
ADMIN_INFO=$(ADDRESS="$ADDRESS" DEV_KEY="$DEV_KEY" ENV_FILE="$BACKEND/.env" node -e '
const fs = require("fs"); const crypto = require("crypto");
const file = process.env.ENV_FILE;
let text = fs.readFileSync(file, "utf8");
const get = (k) => { const m = text.match(new RegExp("^" + k + "=(.*)$", "m")); return m ? m[1].trim() : ""; };
const set = (k, v) => { const re = new RegExp("^" + k + "=.*$", "m"); text = re.test(text) ? text.replace(re, k + "=" + v) : text.replace(/\n?$/, "\n") + k + "=" + v + "\n"; };
set("CHAIN_MODE", "local");
set("LOCAL_RPC_URL", "http://127.0.0.1:8545");
set("REGISTRY_CONTRACT_ADDRESS", process.env.ADDRESS);
set("REGISTRY_SIGNER_PRIVATE_KEY", process.env.DEV_KEY);
if (!get("SESSION_SECRET")) set("SESSION_SECRET", crypto.randomBytes(48).toString("hex"));
let note = "";
if (!get("ADMIN_EMAIL") || !get("ADMIN_PASSWORD")) {
  const pw = "Cl-" + crypto.randomBytes(9).toString("base64url") + "7";
  set("ADMIN_EMAIL", "admin@cyberlens.local");
  set("ADMIN_PASSWORD", pw);
  note = "admin@cyberlens.local / " + pw;
} else note = get("ADMIN_EMAIL") + " / (password in backend/.env)";
fs.writeFileSync(file, text);
console.log(note);
') || fail "Could not update backend/.env"

say "Starting the backend (log: backend/backend.log)"
(cd "$BACKEND" && node src/server.js > backend.log 2>&1) &
BACKEND_PID=$!
wait_for http://localhost:4000/api/health/live "Backend" "$BACKEND/backend.log"
DB_LINE=$(grep -o "Database: .*" "$BACKEND/backend.log" | head -1 | sed 's/ *$//')

say "Starting the website (log: frontend/frontend.log)"
(cd "$FRONTEND" && npx vite --port 5173 --strictPort > frontend.log 2>&1) &
FRONTEND_PID=$!
wait_for http://localhost:5173/ "Website" "$FRONTEND/frontend.log"

trap 'printf "\nStopping CYBERLENS...\n"; kill $FRONTEND_PID $BACKEND_PID $CHAIN_PID 2>/dev/null; exit 0' INT TERM

printf '\n\033[1;32m✔ CYBERLENS is running\033[0m\n'
printf '   Website     http://localhost:5173\n'
printf '   API health  http://localhost:4000/api/health\n'
printf '   Contract    %s (local chain)\n' "$ADDRESS"
printf '   %s\n' "${DB_LINE:-Database: unknown}"
printf '   Admin login %s\n' "$ADMIN_INFO"
printf '\nKeep this window open. Press Ctrl+C to stop everything.\n'
wait
