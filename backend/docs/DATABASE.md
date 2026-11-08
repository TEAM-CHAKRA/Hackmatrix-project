# CYBERLENS: connecting Supabase

The backend can run on one of two databases:

- **In memory** (the default). Data is lost on every restart.
- **Supabase**. Data is permanent. The backend switches to it automatically when two settings are present in `backend/.env`.

The **website never talks to Supabase directly**. Only the backend does, using the secret key. Never put a Supabase key in `frontend/`.

---

## Step 1: Create the CYBERLENS tables (once)

1. Open the Supabase dashboard, then your project, then **SQL Editor**, then **New query**.
2. Open `backend/supabase/schema.sql`, copy all of it, paste it into the editor and press **Run**. You should see "Success. No rows returned".
3. Check **Table Editor**. You should now see six tables that start with `cl_`:

| Table | Holds |
|---|---|
| `cl_users` | Accounts (only password hashes, never passwords) |
| `cl_sessions` | Who is signed in |
| `cl_investigations` | Link and message scan reports |
| `cl_canonical_snapshots` | The exact text that was hashed for the blockchain |
| `cl_registry_entries` | Blockchain registrations, and the Threat Feed |
| `cl_community_reports` | Community reports, votes and moderation status |

Notes on the script:

- It is safe to run again.
- It does not touch any tables you created before; the `cl_` prefix keeps them apart.
- It turns on Row Level Security with no policies. The public anon key can see nothing; only the backend's secret key can.

## Step 2: Copy two values from Supabase

Go to **Project Settings**, then **API Keys** (on older dashboards: **Settings → API**).

| Copy this | Looks like |
|---|---|
| **Project URL** | `https://abcdefghijklmnop.supabase.co` |
| **Secret key**: `service_role` (legacy JWT) or `sb_secret_…` (new) | a long string |

Do **not** use the `anon` / `publishable` key. The backend refuses it with a clear error.

## Step 3: Put them in `backend/.env`

Add these two lines (and never commit `.env`):

```ini
SUPABASE_URL=https://abcdefghijklmnop.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<the secret key>
```

## Step 4: Test the connection

```bash
cd ~/Desktop/Hackmatrix-project/backend
npm install
npm run db:check
```

A working setup prints a ✔ for every table and function, then **"Supabase is connected and ready."**

If you see a ✖, the line tells you what to do:

| Message | Fix |
|---|---|
| `missing — run backend/supabase/schema.sql` | Do Step 1 |
| `key rejected` | Copy the **secret** key again (Step 2) |
| `permission denied` | You used the anon key; use the secret key |
| `cannot reach Supabase` | Check `SUPABASE_URL` and your internet connection |

## Step 5: Run everything

```bash
cd ~/Desktop/Hackmatrix-project
bash start-cyberlens.sh
```

The backend log (`backend/backend.log`) should say `🗄️  Database: Supabase (all tables ready)`. If Supabase is not ready, the backend stops and lists what is missing, instead of starting with half a database.

## Step 6: Check that data really persists

1. Register an account on the website, run a link scan, and submit a community report.
2. In Supabase **Table Editor**, the rows appear in `cl_users`, `cl_investigations` and `cl_community_reports`.
3. Press Ctrl+C and run `bash start-cyberlens.sh` again. You are still signed in, and the scan and the report are still there.

`http://localhost:4000/api/health` shows `"databaseProvider": "supabase"` and `"database": "ok"`.

---

## Good to know

- **Tests never touch your Supabase project.** `npm test` always uses the in-memory database, even when `.env` has Supabase keys.
- **Local blockchain and a persistent database.** The local Hardhat chain is wiped on every restart, but Supabase keeps the old registry rows. When you register a report again, the backend notices the chain record is gone and anchors it again. On Sepolia this cannot happen.
- **Scans interrupted by a restart** are marked "failed: please run the scan again", so the website never waits forever.
- **Admin password**: `ADMIN_PASSWORD` in `.env` is always the admin's password. If you change it, the next start updates the account.
- **Going back to memory**: set `DB_PROVIDER=memory` in `.env`.
- **How it works in code**: `src/store/supabaseRepository.js` implements the same repository contract as the in-memory version (`src/store/repository.js`), so no route changes.
  - All 179 backend tests pass on both databases. The Supabase run used a real Postgres with PostgREST, the same API layer Supabase uses.
  - Updates are atomic field merges done inside Postgres (`cl_merge_record`).
