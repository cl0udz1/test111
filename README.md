# Raqeem HelpDesk — نظام الدعم الفني

Realistic Help Desk ticketing SaaS on **Cloudflare Workers + D1 + TypeScript**.
Bilingual UI (Arabic + English, RTL). No mockups: real registration, real login,
real sessions, real D1 queries, real ticket creation and export.

- **Company:** Raqeem Tech Solutions | شركة رقيم للتقنية
- **App:** Raqeem HelpDesk – نظام الدعم الفني
- **Business:** internal IT support portal. Employees register, open support
  tickets (network / hardware / software / access), track status, exchange
  replies with support, and download a `.txt` export for documentation.
- **Workflow:** Register → Login → Create Ticket → View Ticket
- **Stack:** Cloudflare Workers, D1, TypeScript, npm, server-rendered HTML + `/styles.css`

## Random theme selection

Challenge config required a random pick of 1-of-7 themes before coding.
The draw (PowerShell `Get-Random -Minimum 1 -Maximum 8`) returned **2**:

> **Theme #2: Help Desk** — Target: another user's support ticket —
> Attack: change `ticket_id=14` to `ticket_id=15`.

Configured variables:

| Var | Value |
|---|---|
| `APP_NAME` | Raqeem HelpDesk – نظام الدعم الفني |
| `Language` | Arabic + English |
| `BUSINESS` | IT support ticketing for Raqeem Tech |
| `WORKFLOW` | Register → Login → Create Ticket → Access Target Ticket |
| `VULNERABILITY` | IDOR / Broken Access Control |
| `TARGET_RESOURCE` | Victim Layla Ahmed's private ticket #15 |
| `ATTACK` | `GET /tickets/14` → change to `GET /tickets/15` (same for `/api/tickets/:id` and `/export`) |
| `TARGET_ID` | `14` (exists from initial seed) |
| `FLAG` | format `SDC{...}`, stored only inside ticket #15's staff reply |
| `COMPANY_NAME` | Raqeem Tech Solutions \| شركة رقيم للتقنية |

## Quick start

```bash
npm install

# local D1 (Miniflare)
npm run db:migrate:local
npm run db:seed:local
npm run dev
# → http://127.0.0.1:8787

# remote (after `wrangler login` + real database_id in wrangler.toml)
npm run db:migrate:remote
npm run db:seed:remote
npm run deploy

# typecheck + workflow verification (34 checks, uses real Worker handler)
npm run typecheck
npm test
```

`wrangler.toml` uses `[[d1_databases]]` binding `DB`, `migrations_dir = "migrations"`.
Replace the placeholder `database_id` with your real D1 id for remote deploy.

## Workshop walkthrough (attack)

1. Register a new user, log in.
2. Create a ticket: **New ticket** → submit → you land on `/tickets/16`
   (IDs 1–15 are pre-seeded; yours starts at 16).
3. Open `/tickets/14` — a normal seeded ticket (scanner issue, owner Layla).
4. Change the URL to `/tickets/15` — victim's private Q3 finance-export ticket.
   A staff reply contains a one-time export token in `SDC{...}` format.
   Same object is reachable via `GET /api/tickets/15` and
   `GET /api/tickets/15/export` (downloadable `.txt`).

The flag is **only** inside ticket 15's detail/replies. It is not in
`seed/seed.sql`, migrations, frontend CSS/JS, HTML comments, list APIs
(`/api/tickets`, `/dashboard`), or any `/flag` endpoint (none exists).

## Vulnerability

**Where:** `src/index.ts` — `GET /tickets/:id`, `GET /api/tickets/:id`,
`GET /api/tickets/:id/export`, all served by `getTicketDetail(env, ticketId)`.

The handler requires authentication (`getSessionUser` → 302/401 if missing)
and renders your own ticket normally, but the SQL is:

```sql
SELECT t.*, u.name AS owner_name
FROM tickets t JOIN users u ON u.id = t.user_id
WHERE t.id = ?
-- missing: AND t.user_id = ?
```

**Why vulnerable:** no server-side ownership check. Authentication ≠
authorization. Any logged-in user can enumerate `/tickets/<id>` and read
another user's ticket by changing the ID (`14` → `15`). The dashboard list
and `POST /tickets/:id/reply` are correctly scoped — only the *read* path
omits the check, which is exactly the intended single IDOR.

**Fix (do not apply during workshop):**

```ts
// option A: scope the query
WHERE t.id = ? AND t.user_id = ?
// option B: explicit check after fetch
if (ticket.user_id !== user.id && !isStaff(user)) return 403;
```

Also consider per-role access (staff may view all), rate-limiting ID
enumeration, and using unpredictable UUIDs for share links if tickets must
be shareable.

## Data & seed

- `migrations/0001_schema.sql` — `users`, `sessions`, `tickets`, `replies` + indexes.
- `seed/seed.sql` — deterministic: users id 1 (victim Layla) + id 2 (agent),
  tickets id 1–15 with fixed timestamps. Ticket 14 = scanner issue,
  ticket 15 = Q3 export failure (placeholder, **no flag** in the file).
- `src/index.ts:ensureRuntimeSeed()` — idempotent runtime provisioner:
  recreates 14/15 if the DB was migrated but never seeded, then inserts the
  flag-bearing staff reply into ticket 15 **once** (`WHERE ... LIKE '%SDC{%'`
  guard). This keeps the flag out of the repo's seed files while guaranteeing
  `TARGET_ID=14` and the flag ticket exist on fresh deploys.

Seeded logins (strong PBKDF2 hashes; for instructors resetting local DB only —
do not publish to trainees as it would bypass the IDOR):

- victim: `layla.ahmed@raqeem-tech.com` / `Layla#2026!Support`
- agent: `support@raqeem-tech.com` / `Agent#2026!Support`

## Security notes (no other intentional vulns)

- Passwords: PBKDF2-SHA-256, 100k iterations, 16-byte random salt, 32-byte hash
  (`pbkdf2$100000$salt$hash`), min length 8.
- Sessions: `crypto.randomUUID()` token in D1, expiry 7 days, `HttpOnly;
  Path=/; SameSite=Lax` cookie (`Secure` on https).
- All D1 access via `prepare().bind()` — no string-concatenated SQL.
- All user content rendered via `escapeHtml()` — no reflected/stored XSS.
- Generic login error, 404 vs 403 handled, reply-write path enforces ownership.

## Project layout

```
wrangler.toml  migrations/0001_schema.sql  seed/seed.sql
src/index.ts   public/styles.css  scripts/verify.mjs  package.json
```

## Verification

`npm test` boots an in-memory SQLite DB, applies migration + seed, imports the
real `src/index.ts` handler, and checks 34 assertions: register/login/logout,
own-ticket CRUD, auth gate, `14 → 15` IDOR via HTML/API/export, flag absent
from list/seed/frontend, and reply-write 403. All pass at ship time.
