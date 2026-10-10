// End-to-end workflow verification using node:sqlite + the real Worker handler.
// Run: npm run test  (requires Node 22.5+ for node:sqlite, Node 26 recommended)
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");

function read(p) {
  return fs.readFileSync(path.join(root, p), "utf8");
}

// --- Minimal D1 shim over node:sqlite ---
function createD1(db) {
  return {
    prepare(sql) {
      return {
        bind(...params) {
          return {
            first() {
              try {
                const stmt = db.prepare(sql);
                const row = stmt.get(...params);
                return row === undefined ? null : row;
              } catch (e) {
                throw e;
              }
            },
            all() {
              const stmt = db.prepare(sql);
              const rows = stmt.all(...params);
              return { results: rows };
            },
            run() {
              const stmt = db.prepare(sql);
              const info = stmt.run(...params);
              return { meta: { last_row_id: Number(info.lastInsertRowid), changes: Number(info.changes) }, success: true };
            },
          };
        },
        first() {
          const stmt = db.prepare(sql);
          const row = stmt.get();
          return row === undefined ? null : row;
        },
        all() {
          const stmt = db.prepare(sql);
          return { results: stmt.all() };
        },
        run() {
          const stmt = db.prepare(sql);
          const info = stmt.run();
          return { meta: { last_row_id: Number(info.lastInsertRowid), changes: Number(info.changes) }, success: true };
        },
      };
    },
    exec(sql) {
      db.exec(sql);
    },
  };
}

const checks = [];
function check(name, cond, extra = "") {
  checks.push({ name, ok: !!cond });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra && !cond ? "  — " + extra : ""}`);
  if (!cond) process.exitCode = 1;
}

console.log("== Raqeem HelpDesk verification ===");

// 0. Static guarantees: flag must NOT be in seed/frontend
const seedSql = read("seed/seed.sql");
const migration = read("migrations/0001_schema.sql");
const pkg = read("package.json");
check("seed.sql contains TARGET_ID 14", /\(14, 1,/.test(seedSql));
check("seed.sql contains ticket 15", /\(15, 1,/.test(seedSql));
check("seed.sql does NOT contain flag (no SDC{)", !/SDC\{/.test(seedSql), "seed must not embed flag");
check("migration does NOT contain flag", !/SDC\{/.test(migration));
const css = read("public/styles.css");
check("frontend CSS does NOT contain flag", !/SDC\{/.test(css));
const workerSrc = read("src/index.ts");
check("no /flag route in worker", !/path === "\/flag"|pathname === "\/flag"|"\/flag".*fetch|app\.get\("\/flag"/.test(workerSrc), "must not expose /flag route");
check("worker has ownership-fix comment", /user_id.*user\.id|AND t\.user_id/i.test(workerSrc));

// 1. Boot DB: migrations + seed
const db = new DatabaseSync(":memory:");
db.exec("PRAGMA foreign_keys = ON;");
db.exec(migration);
db.exec(seedSql);
const env = { DB: createD1(db) };

// Import the real Worker (Node 26 strips TS types automatically)
const worker = (await import(pathToFileURL(path.join(root, "src/index.ts")).href)).default;
if (!worker?.fetch) {
  console.error("FAIL  worker has no fetch export");
  process.exit(1);
}

const jar = {};
function storeCookies(res) {
  const set = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const c of set) {
    const m = c.match(/^session=([^;]*)/);
    if (m) jar.session = decodeURIComponent(m[1]);
  }
}
function cookieHeader() {
  return jar.session ? { Cookie: `session=${encodeURIComponent(jar.session)}` } : {};
}
async function req(pathname, opts = {}) {
  const headers = { ...(opts.headers || {}), ...cookieHeader() };
  const res = await worker.fetch(new Request(`https://test.local${pathname}`, { ...opts, headers }), env);
  storeCookies(res);
  return res;
}
function form(obj) {
  const fd = new FormData();
  for (const [k, v] of Object.entries(obj)) fd.append(k, v);
  return fd;
}

// 2. Health
{
  const r = await req("/health");
  check("GET /health 200", r.status === 200);
}

// 3. TARGET_ID=14 exists from seed (unauthenticated direct DB check)
{
  const row = db.prepare("SELECT id, user_id, title FROM tickets WHERE id = 14").get();
  check("ticket 14 exists from seed", !!row, JSON.stringify(row));
  const row15 = db.prepare("SELECT id, user_id, title FROM tickets WHERE id = 15").get();
  check("ticket 15 exists from seed", !!row15);
  check("ticket 15 owned by victim (user 1)", row15 && row15.user_id === 1);
}

// 4. Register new attacker user
{
  const r = await req("/register", { method: "POST", body: form({ name: "Attacker User", email: "attacker@example.com", password: "Attacker#12345" }) });
  check("POST /register redirects (302)", r.status === 302, `got ${r.status}`);
  check("register sets HttpOnly session cookie", !!jar.session, "no session cookie");
  const setCookies = r.headers.getSetCookie ? r.headers.getSetCookie().join(";") : "";
  check("session cookie is HttpOnly", /HttpOnly/i.test(setCookies));
}

// 5. Dashboard works (own tickets, initially empty)
{
  const r = await req("/dashboard");
  const t = await r.text();
  check("GET /dashboard 200 for new user", r.status === 200, `got ${r.status}`);
  check("dashboard shows My Tickets", /My Tickets|تذاكر/.test(t));
  check("dashboard does NOT leak victim tickets", !/Scanner not detected|Q3 financial report/.test(t), "victim data leaked in list");
}

// 6. Create ticket (normal workflow)
let ownId = 0;
{
  const r = await req("/tickets", { method: "POST", body: form({ title: "My printer is jammed", category: "Hardware", priority: "Medium", description: "Office printer on floor 3 shows jam error, need help urgently please." }) });
  const loc = r.headers.get("Location") || "";
  const m = loc.match(/\/tickets\/(\d+)/);
  ownId = m ? parseInt(m[1], 10) : 0;
  check("POST /tickets creates ticket (redirect)", r.status === 302 && ownId >= 16, `Location=${loc}`);
  const d = await req(`/tickets/${ownId}`);
  const t = await d.text();
  check("own ticket viewable normally", d.status === 200 && /My printer is jammed/.test(t));
}

// 7. Unauthenticated access must require login
{
  const saved = jar.session;
  delete jar.session;
  const r = await req("/tickets/15", { redirect: "manual" });
  check("unauthenticated /tickets/15 requires login (302 to /login)", r.status === 302, `got ${r.status}`);
  jar.session = saved;
}

// 8. Vulnerable action: 14 -> 15 (IDOR)
{
  const r14 = await req("/tickets/14");
  const t14 = await r14.text();
  check("GET /tickets/14 (seed ticket) 200", r14.status === 200, `got ${r14.status}`);
  check("ticket 14 shows victim data (not own)", /Scanner not detected|Another user/.test(t14));

  const r15 = await req("/tickets/15");
  const t15 = await r15.text();
  const flagMatch = t15.match(/SDC\{[^}]+\}/);
  check("GET /tickets/15 (IDOR) 200", r15.status === 200, `got ${r15.status}`);
  check("ticket 15 contains flag SDC{...}", !!flagMatch, "no flag in ticket 15 HTML");
  if (flagMatch) console.log(`      flag via HTML IDOR: ${flagMatch[0]}`);

  const api = await req("/api/tickets/15");
  const j = await api.json();
  const apiText = JSON.stringify(j);
  const apiFlag = apiText.match(/SDC\{[^}]+\}/);
  check("GET /api/tickets/15 (IDOR) contains flag", api.status === 200 && !!apiFlag);
  if (apiFlag) console.log(`      flag via API IDOR: ${apiFlag[0]}`);

  const exp = await req("/api/tickets/15/export");
  const expText = await exp.text();
  const expFlag = expText.match(/SDC\{[^}]+\}/);
  check("GET /api/tickets/15/export contains flag", exp.status === 200 && !!expFlag);
  check("export is downloadable attachment", (exp.headers.get("Content-Disposition") || "").includes("attachment"));

  const list = await req("/api/tickets");
  const listJson = await list.json();
  const listText = JSON.stringify(listJson);
  check("GET /api/tickets list does NOT contain flag", !/SDC\{/.test(listText));
  check("list does NOT include victim ticket 15", !listText.includes('"id":15'));
  check("list includes own ticket", listText.includes(`"id":${ownId}`));
}

// 9. Write path stays secure (only read is vulnerable)
{
  const r = await req("/tickets/15/reply", { method: "POST", body: form({ body: "trying to post to чужой ticket" }) });
  check("POST reply to чужой ticket is 403 (write secured)", r.status === 403, `got ${r.status}`);
}

// 10. Real auth: wrong password rejected, logout works
{
  const saved = jar.session;
  delete jar.session;
  const bad = await req("/login", { method: "POST", body: form({ email: "attacker@example.com", password: "wrongpass123" }) });
  check("login with wrong password is 401", bad.status === 401, `got ${bad.status}`);
  jar.session = saved;
  const lo = await req("/logout", { method: "POST" });
  check("POST /logout 302", lo.status === 302);
  const after = await req("/dashboard", { redirect: "manual" });
  check("dashboard after logout requires login", after.status === 302);
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n== ${checks.length - failed.length}/${checks.length} checks passed ==`);
if (failed.length) {
  console.log("Failed:", failed.map((f) => f.name).join("; "));
  process.exit(1);
} else {
  console.log("Workflow verified: Register → Login → Create → Access own → IDOR 14→15 → flag only via IDOR.");
}
