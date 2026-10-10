/**
 * Raqeem HelpDesk — نظام الدعم الفني
 * Help Desk ticketing SaaS on Cloudflare Workers + D1.
 *
 * Theme randomly selected: #2 Help Desk
 * Target: another user's support ticket (ticket 15, victim: Layla Ahmed)
 * Attack: change ticket_id=14 to ticket_id=15
 *
 * WORKFLOW: Register → Login → Create Ticket → View Ticket
 * VULN: IDOR / Broken Access Control on ticket detail (see getTicketDetail)
 */

export interface Env {
  DB: D1Database;
  APP_NAME?: string;
}

interface User {
  id: number;
  name: string;
  email: string;
  password_hash: string;
  created_at: string;
}

interface Ticket {
  id: number;
  user_id: number;
  title: string;
  category: string;
  priority: string;
  status: string;
  description: string;
  created_at: string;
  updated_at: string;
  owner_name?: string;
}

interface Reply {
  id: number;
  ticket_id: number;
  user_id: number;
  body: string;
  is_staff: number;
  created_at: string;
  author_name?: string;
}

// ---------------------------------------------------------------------------
// Backend-only flag provisioning.
// The flag lives ONLY inside ticket 15 (victim's private ticket) at runtime.
// It is NOT present in seed/seed.sql, frontend JS, HTML comments, or /flag routes.
// ---------------------------------------------------------------------------
const FLAG = "SDC{h3lp_d3sk_t1ck3t_id0r_8f2k41}";
const VICTIM_EMAIL = "layla.ahmed@raqeem-tech.com";
const AGENT_EMAIL = "support@raqeem-tech.com";

const ALLOWED_CATEGORIES = ["General", "Network", "Hardware", "Software", "Access"];
const ALLOWED_PRIORITIES = ["Low", "Medium", "High", "Urgent"];
const ALLOWED_STATUS = ["open", "in_progress", "resolved", "closed"];

// ----------------------------- crypto helpers ------------------------------

function bytesToHex(bytes: Uint8Array | ArrayBuffer): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations: 100000 },
    key,
    256
  );
  return `pbkdf2$100000$${bytesToHex(salt)}$${bytesToHex(bits)}`;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  try {
    const parts = stored.split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
    const iterations = parseInt(parts[1], 10);
    const salt = hexToBytes(parts[2]);
    const expectedHex = parts[3];
    if (!Number.isFinite(iterations) || salt.length === 0) return false;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
      key,
      expectedHex.length * 4
    );
    return timingSafeEqual(bytesToHex(bits), expectedHex);
  } catch {
    return false;
  }
}

// ------------------------------- html helpers ------------------------------

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function statusLabel(status: string): string {
  switch (status) {
    case "open":
      return "مفتوحة / Open";
    case "in_progress":
      return "قيد المعالجة / In Progress";
    case "resolved":
      return "محلولة / Resolved";
    case "closed":
      return "مغلقة / Closed";
    default:
      return escapeHtml(status);
  }
}

function layout(title: string, body: string, user: User | null): string {
  const nav = user
    ? `<span class="nav-user">مرحباً ${escapeHtml(user.name)} (${escapeHtml(user.email)})</span>
       <a href="/dashboard">لوحتي / Dashboard</a>
       <a href="/tickets/new">تذكرة جديدة / New</a>
       <form method="POST" action="/logout" style="display:inline"><button class="linkbtn" type="submit">خروج / Logout</button></form>`
    : `<a href="/login">دخول / Login</a><a href="/register">حساب جديد / Register</a>`;
  return `<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} — Raqeem HelpDesk</title>
<link rel="stylesheet" href="/styles.css">
</head>
<body>
<header class="topbar">
  <div class="brand"><strong>Raqeem HelpDesk</strong><span>نظام الدعم الفني — Raqeem Tech Solutions</span></div>
  <nav>${nav}</nav>
</header>
<main class="container">${body}</main>
<footer class="footer">Raqeem Tech Solutions | شركة رقيم للتقنية — Internal IT Support Portal · <a href="/">الرئيسية / Home</a></footer>
</body>
</html>`;
}

function errorPage(message: string, user: User | null, backHref = "/"): string {
  return layout(
    "خطأ",
    `<div class="card"><h2>حدث خطأ / Error</h2><p class="err">${escapeHtml(message)}</p><p><a class="btn" href="${escapeHtml(backHref)}">رجوع / Back</a></p></div>`,
    user
  );
}

// ------------------------------ session helpers ----------------------------

function getCookie(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  const parts = header.split(";");
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    if (k === name) return decodeURIComponent(p.slice(idx + 1).trim());
  }
  return null;
}

function sqliteNowPlusDays(days: number): string {
  const d = new Date(Date.now() + days * 86400 * 1000);
  return d.toISOString().slice(0, 19).replace("T", " ");
}

function makeSessionCookie(token: string, reqUrl: string): string {
  const secure = reqUrl.startsWith("https://") ? "; Secure" : "";
  return `session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800${secure}`;
}

function clearSessionCookie(): string {
  return `session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`;
}

async function getSessionUser(request: Request, env: Env): Promise<User | null> {
  const token = getCookie(request, "session");
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.name, u.email, u.password_hash, u.created_at
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.expires_at > datetime('now')`
  )
    .bind(token)
    .first<User>();
  return row ?? null;
}

async function createSession(env: Env, userId: number): Promise<string> {
  const token = crypto.randomUUID();
  const expires = sqliteNowPlusDays(7);
  await env.DB.prepare(`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)`)
    .bind(token, userId, expires)
    .run();
  return token;
}

// --------------------------- deterministic runtime seed --------------------
// Ensures TARGET_ID=14 exists and ticket 15 (victim private ticket) exists,
// then provisions the flag ONLY inside ticket 15's staff reply.
// Safe to run on every request (idempotent, OR IGNORE + LIKE guard).

async function ensureRuntimeSeed(env: Env): Promise<void> {
  try {
    // Victim + agent must exist (matches seed/seed.sql). If DB was migrated
    // but never seeded, create them here with the same deterministic IDs.
    const victim = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`)
      .bind(VICTIM_EMAIL)
      .first<{ id: number }>();
    if (!victim) {
      const hash = await hashPassword("Layla#2026!Support");
      await env.DB.prepare(
        `INSERT OR IGNORE INTO users (id, name, email, password_hash, created_at) VALUES (1, 'Layla Ahmed', ?, ?, '2026-01-05 09:00:00')`
      )
        .bind(VICTIM_EMAIL, hash)
        .run();
    }
    const agent = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`)
      .bind(AGENT_EMAIL)
      .first<{ id: number }>();
    if (!agent) {
      const hash = await hashPassword("Agent#2026!Support");
      await env.DB.prepare(
        `INSERT OR IGNORE INTO users (id, name, email, password_hash, created_at) VALUES (2, 'Support Agent', ?, ?, '2026-01-05 09:00:00')`
      )
        .bind(AGENT_EMAIL, hash)
        .run();
    }

    const t14 = await env.DB.prepare(`SELECT id FROM tickets WHERE id = 14`).first<{ id: number }>();
    if (!t14) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO tickets (id, user_id, title, category, priority, status, description, created_at, updated_at)
         VALUES (14, 1, 'Scanner not detected - finance', 'Hardware', 'Medium', 'open',
         'Canon scanner in finance room is not detected by Document Scan app since Tuesday. USB cable checked, power on. Asset SC-011.',
         '2026-02-12 09:30:00', '2026-02-12 09:30:00')`
      ).run();
    }
    const t15 = await env.DB.prepare(`SELECT id FROM tickets WHERE id = 15`).first<{ id: number }>();
    if (!t15) {
      await env.DB.prepare(
        `INSERT OR IGNORE INTO tickets (id, user_id, title, category, priority, status, description, created_at, updated_at)
         VALUES (15, 1, 'Q3 financial report export fails - error 0x8004', 'Software', 'Urgent', 'in_progress',
         'When exporting the Q3 consolidated financial report from ERP as PDF, it fails with error 0x8004 after 2 minutes. This is needed urgently for the external audit next week. File size ~180MB. Tried Chrome and Edge.',
         '2026-02-13 10:15:00', '2026-02-13 10:15:00')`
      ).run();
    }

    // Provision flag reply once.
    const hasFlag = await env.DB.prepare(
      `SELECT id FROM replies WHERE ticket_id = 15 AND body LIKE '%SDC{%' LIMIT 1`
    ).first<{ id: number }>();
    if (!hasFlag) {
      const agentRow = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`)
        .bind(AGENT_EMAIL)
        .first<{ id: number }>();
      const agentId = agentRow?.id ?? 2;
      const flagReply =
        `Hi Layla,\n\nThanks for the logs. I reproduced error 0x8004 on large exports — it is a timeout on the report worker.\n\n` +
        `I generated a secure one-time export token for the Q3 consolidated report so audit is not blocked. ` +
        `On the ERP export page choose "Resume with token" and enter:\n\n${FLAG}\n\n` +
        `Keep this token private (it grants access to the finance export only) and use it within 48h. ` +
        `We will deploy the permanent fix on Sunday.\n\n— Ahmed, IT Support (Raqeem Tech)`;
      await env.DB.prepare(
        `INSERT INTO replies (ticket_id, user_id, body, is_staff, created_at) VALUES (15, ?, ?, 1, datetime('now'))`
      )
        .bind(agentId, flagReply)
        .run();
      await env.DB.prepare(`UPDATE tickets SET updated_at = datetime('now') WHERE id = 15`).run();
    }
  } catch {
    // Seeding must never break the app; ignore errors (e.g. tables not migrated yet).
  }
}

// ------------------------------ data access --------------------------------
// NOTE (vulnerability location):
// getTicketDetail intentionally checks authentication upstream but does NOT
// check ticket.user_id == session user. That is the IDOR. See handler for
// GET /tickets/:id and GET /api/tickets/:id.

async function getTicketDetail(env: Env, ticketId: number): Promise<{ ticket: Ticket; replies: Reply[] } | null> {
  const ticket = await env.DB.prepare(
    `SELECT t.*, u.name AS owner_name FROM tickets t JOIN users u ON u.id = t.user_id WHERE t.id = ?`
  )
    .bind(ticketId)
    .first<Ticket>();
  if (!ticket) return null;
  const { results } = await env.DB.prepare(
    `SELECT r.*, u.name AS author_name FROM replies r JOIN users u ON u.id = r.user_id WHERE r.ticket_id = ? ORDER BY r.id ASC`
  )
    .bind(ticketId)
    .all<Reply>();
  return { ticket, replies: (results ?? []) as Reply[] };
}

// ------------------------------- handlers ----------------------------------

function redirectWithCookie(url: string, cookie: string): Response {
  return new Response(null, {
    status: 302,
    headers: { Location: url, "Set-Cookie": cookie },
  });
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    await ensureRuntimeSeed(env);

    try {
      // ---- static css ----
      if (path === "/styles.css" && method === "GET") {
        return new Response(CSS, { headers: { "Content-Type": "text/css; charset=utf-8", "Cache-Control": "public, max-age=3600" } });
      }

      // ---- health ----
      if (path === "/health" && method === "GET") {
        return json({ ok: true, app: "raqeem-helpdesk" });
      }

      // ---- landing ----
      if (path === "/" && method === "GET") {
        const user = await getSessionUser(request, env);
        if (user) return Response.redirect(new URL("/dashboard", url).toString(), 302);
        return new Response(
          layout(
            "الرئيسية",
            `<div class="hero">
              <h1>نظام الدعم الفني <small>Raqeem HelpDesk</small></h1>
              <p>البوابة الداخلية للدعم التقني في <strong>شركة رقيم للتقنية</strong> — افتح تذكرة، تابع حالتها، وتواصل مع فريق الدعم.</p>
              <p class="muted">Internal IT support portal — open a ticket, track its status, and chat with support.</p>
              <div class="row"><a class="btn" href="/register">إنشاء حساب / Register</a><a class="btn secondary" href="/login">تسجيل الدخول / Login</a></div>
              <div class="grid3">
                <div class="feat"><h3>تذاكر منظمة</h3><p>تصنيف حسب القسم والأولوية مع رقم تتبع لكل طلب.</p></div>
                <div class="feat"><h3>متابعة مباشرة</h3><p>ردود فريق الدعم تظهر داخل التذكرة مع إشعار الحالة.</p></div>
                <div class="feat"><h3>تصدير وطباعة</h3><p>حمّل نسخة نصية من تذكرتك للتوثيق أو الطباعة.</p></div>
              </div>
            </div>`,
            null
          ),
          { headers: { "Content-Type": "text/html; charset=utf-8" } }
        );
      }

      // ---- register ----
      if (path === "/register" && method === "GET") {
        const user = await getSessionUser(request, env);
        if (user) return Response.redirect(new URL("/dashboard", url).toString(), 302);
        return new Response(
          layout(
            "حساب جديد",
            `<div class="card narrow"><h2>إنشاء حساب جديد / Register</h2>
            <form method="POST" action="/register">
              <label>الاسم الكامل / Full name<input name="name" required minlength="2" maxlength="80" placeholder="مثال: محمد العمري"></label>
              <label>البريد الإلكتروني / Email<input name="email" type="email" required placeholder="you@company.com"></label>
              <label>كلمة المرور / Password (8+ chars)<input name="password" type="password" required minlength="8" placeholder="••••••••"></label>
              <button class="btn" type="submit">تسجيل / Sign up</button>
            </form><p class="muted">لديك حساب؟ <a href="/login">سجّل الدخول</a></p></div>`,
            null
          ),
          { headers: { "Content-Type": "text/html; charset=utf-8" } }
        );
      }

      if (path === "/register" && method === "POST") {
        const form = await request.formData();
        const name = String(form.get("name") ?? "").trim();
        const email = String(form.get("email") ?? "").trim().toLowerCase();
        const password = String(form.get("password") ?? "");
        if (name.length < 2 || name.length > 80) {
          return new Response(errorPage("الاسم يجب أن يكون بين 2 و 80 حرفاً. / Name must be 2-80 chars.", null, "/register"), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        if (!isValidEmail(email) || email.length > 120) {
          return new Response(errorPage("بريد إلكتروني غير صالح. / Invalid email.", null, "/register"), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        if (password.length < 8 || password.length > 200) {
          return new Response(errorPage("كلمة المرور 8 أحرف على الأقل. / Password min 8 chars.", null, "/register"), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        const existing = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first<{ id: number }>();
        if (existing) {
          return new Response(errorPage("هذا البريد مسجل مسبقاً. جرّب تسجيل الدخول. / Email already registered.", null, "/login"), { status: 409, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        const hash = await hashPassword(password);
        const result = await env.DB.prepare(`INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)`)
          .bind(name, email, hash)
          .run();
        const userId = Number(result.meta.last_row_id);
        const token = await createSession(env, userId);
        return redirectWithCookie("/dashboard", makeSessionCookie(token, url.origin));
      }

      // ---- login ----
      if (path === "/login" && method === "GET") {
        const user = await getSessionUser(request, env);
        if (user) return Response.redirect(new URL("/dashboard", url).toString(), 302);
        return new Response(
          layout(
            "دخول",
            `<div class="card narrow"><h2>تسجيل الدخول / Login</h2>
            <form method="POST" action="/login">
              <label>البريد الإلكتروني / Email<input name="email" type="email" required></label>
              <label>كلمة المرور / Password<input name="password" type="password" required></label>
              <button class="btn" type="submit">دخول / Sign in</button>
            </form><p class="muted">لا تملك حساباً؟ <a href="/register">أنشئ حساباً</a></p></div>`,
            null
          ),
          { headers: { "Content-Type": "text/html; charset=utf-8" } }
        );
      }

      if (path === "/login" && method === "POST") {
        const form = await request.formData();
        const email = String(form.get("email") ?? "").trim().toLowerCase();
        const password = String(form.get("password") ?? "");
        const row = await env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first<User>();
        const ok = row ? await verifyPassword(password, row.password_hash) : false;
        if (!row || !ok) {
          return new Response(errorPage("بيانات الدخول غير صحيحة. / Invalid email or password.", null, "/login"), { status: 401, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        const token = await createSession(env, row.id);
        return redirectWithCookie("/dashboard", makeSessionCookie(token, url.origin));
      }

      // ---- logout ----
      if (path === "/logout" && method === "POST") {
        const token = getCookie(request, "session");
        if (token) {
          await env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(token).run();
        }
        return new Response(null, { status: 302, headers: { Location: "/", "Set-Cookie": clearSessionCookie() } });
      }

      // ---- auth gate from here ----
      const user = await getSessionUser(request, env);
      const needsAuth =
        path === "/dashboard" ||
        path === "/tickets/new" ||
        path === "/tickets" ||
        path.startsWith("/tickets/") ||
        path.startsWith("/api/tickets");
      if (needsAuth && !user) {
        if (path.startsWith("/api/")) return json({ error: "unauthorized" }, 401);
        return Response.redirect(new URL("/login", url).toString(), 302);
      }

      // ---- dashboard (SECURE: only own tickets) ----
      if (path === "/dashboard" && method === "GET") {
        const { results } = await env.DB.prepare(
          `SELECT id, title, category, priority, status, created_at FROM tickets WHERE user_id = ? ORDER BY id DESC`
        )
          .bind(user!.id)
          .all<Ticket>();
        const rows = (results ?? []) as Ticket[];
        const list =
          rows.length === 0
            ? `<p class="muted">لا توجد تذاكر بعد. أنشئ أول تذكرة دعم. / No tickets yet. Create your first ticket.</p>`
            : `<table class="tbl"><thead><tr><th>#</th><th>العنوان / Title</th><th>التصنيف</th><th>الأولوية</th><th>الحالة / Status</th><th>التاريخ</th></tr></thead><tbody>` +
              rows
                .map(
                  (t) =>
                    `<tr><td>${t.id}</td><td><a href="/tickets/${t.id}">${escapeHtml(t.title)}</a></td><td>${escapeHtml(t.category)}</td><td>${escapeHtml(t.priority)}</td><td><span class="badge">${escapeHtml(t.status)}</span></td><td class="muted">${escapeHtml(t.created_at)}</td></tr>`
                )
                .join("") +
              `</tbody></table>`;
        return new Response(
          layout(
            "لوحتي",
            `<div class="row-between"><h2>تذاكري / My Tickets</h2><a class="btn" href="/tickets/new">+ تذكرة جديدة / New ticket</a></div>
            ${list}
            <div class="card"><h3>فتح تذكرة برقمها / Open ticket by ID</h3>
            <p class="muted">إذا شاركك زميل رابط تذكرة، أدخل رقمها هنا. / If a colleague shared a ticket link, enter its ID.</p>
            <form method="GET" action="/tickets/jump" class="inline-form"><input name="id" inputmode="numeric" placeholder="مثال: 14" required><button class="btn secondary" type="submit">فتح / Open</button></form></div>`,
            user
          ),
          { headers: { "Content-Type": "text/html; charset=utf-8" } }
        );
      }

      // ---- jump helper: /tickets/jump?id=14 -> /tickets/14 ----
      if (path === "/tickets/jump" && method === "GET") {
        const idParam = url.searchParams.get("id") ?? "";
        const id = parseInt(idParam, 10);
        if (!Number.isInteger(id) || id <= 0) {
          return new Response(errorPage("رقم تذكرة غير صالح. / Invalid ticket id.", user, "/dashboard"), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        return Response.redirect(new URL(`/tickets/${id}`, url).toString(), 302);
      }

      // ---- new ticket form ----
      if (path === "/tickets/new" && method === "GET") {
        return new Response(
          layout(
            "تذكرة جديدة",
            `<div class="card narrow"><h2>فتح تذكرة دعم / New support ticket</h2>
            <form method="POST" action="/tickets">
              <label>العنوان / Title<input name="title" required minlength="3" maxlength="120" placeholder="مثال: الطابعة لا تعمل"></label>
              <label>التصنيف / Category<select name="category">${ALLOWED_CATEGORIES.map((c) => `<option>${c}</option>`).join("")}</select></label>
              <label>الأولوية / Priority<select name="priority">${ALLOWED_PRIORITIES.map((p) => `<option>${p}</option>`).join("")}</select></label>
              <label>الوصف / Description<textarea name="description" required minlength="10" maxlength="5000" rows="6" placeholder="اشرح المشكلة بالتفصيل: الجهاز، الخطوات، رسالة الخطأ..."></textarea></label>
              <button class="btn" type="submit">إرسال / Submit</button>
            </form></div>`,
            user
          ),
          { headers: { "Content-Type": "text/html; charset=utf-8" } }
        );
      }

      // ---- create ticket ----
      if (path === "/tickets" && method === "POST") {
        const form = await request.formData();
        const title = String(form.get("title") ?? "").trim();
        const category = String(form.get("category") ?? "General");
        const priority = String(form.get("priority") ?? "Medium");
        const description = String(form.get("description") ?? "").trim();
        if (title.length < 3 || title.length > 120) {
          return new Response(errorPage("العنوان 3-120 حرف. / Title 3-120 chars.", user, "/tickets/new"), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        if (!ALLOWED_CATEGORIES.includes(category) || !ALLOWED_PRIORITIES.includes(priority)) {
          return new Response(errorPage("تصنيف أو أولوية غير صالحة. / Invalid category/priority.", user, "/tickets/new"), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        if (description.length < 10 || description.length > 5000) {
          return new Response(errorPage("الوصف 10-5000 حرف. / Description 10-5000 chars.", user, "/tickets/new"), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        const result = await env.DB.prepare(
          `INSERT INTO tickets (user_id, title, category, priority, status, description) VALUES (?, ?, ?, ?, 'open', ?)`
        )
          .bind(user!.id, title, category, priority, description)
          .run();
        const newId = Number(result.meta.last_row_id);
        return Response.redirect(new URL(`/tickets/${newId}`, url).toString(), 302);
      }

      // ---- API list (SECURE) ----
      if (path === "/api/tickets" && method === "GET") {
        const { results } = await env.DB.prepare(
          `SELECT id, title, category, priority, status, created_at, updated_at FROM tickets WHERE user_id = ? ORDER BY id DESC`
        )
          .bind(user!.id)
          .all();
        return json({ tickets: results ?? [] });
      }

      // ---- API detail + export + HTML detail share getTicketDetail ----
      const apiDetailMatch = path.match(/^\/api\/tickets\/(\d+)$/);
      if (apiDetailMatch && method === "GET") {
        const ticketId = parseInt(apiDetailMatch[1], 10);
        // VULNERABLE: authenticated but no ownership check.
        const detail = await getTicketDetail(env, ticketId);
        if (!detail) return json({ error: "not_found" }, 404);
        return json({
          id: detail.ticket.id,
          title: detail.ticket.title,
          category: detail.ticket.category,
          priority: detail.ticket.priority,
          status: detail.ticket.status,
          description: detail.ticket.description,
          created_at: detail.ticket.created_at,
          updated_at: detail.ticket.updated_at,
          owner: detail.ticket.owner_name,
          replies: detail.replies.map((r) => ({
            id: r.id,
            body: r.body,
            is_staff: r.is_staff === 1,
            author: r.author_name,
            created_at: r.created_at,
          })),
        });
      }

      const exportMatch = path.match(/^\/api\/tickets\/(\d+)\/export$/);
      if (exportMatch && method === "GET") {
        const ticketId = parseInt(exportMatch[1], 10);
        // VULNERABLE: same missing ownership check (same business object).
        const detail = await getTicketDetail(env, ticketId);
        if (!detail) return json({ error: "not_found" }, 404);
        const lines = [
          `Raqeem Tech Solutions - HelpDesk export`,
          `Ticket #${detail.ticket.id}: ${detail.ticket.title}`,
          `Category: ${detail.ticket.category} | Priority: ${detail.ticket.priority} | Status: ${detail.ticket.status}`,
          `Opened by: ${detail.ticket.owner_name} at ${detail.ticket.created_at}`,
          `Updated: ${detail.ticket.updated_at}`,
          ``,
          `Description:`,
          detail.ticket.description,
          ``,
          `Replies (${detail.replies.length}):`,
          ...detail.replies.flatMap((r) => [`- [${r.created_at}] ${r.author_name}${r.is_staff ? " (staff)" : ""}:`, r.body, ``]),
        ];
        return new Response(lines.join("\n"), {
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Disposition": `attachment; filename="ticket-${detail.ticket.id}.txt"`,
          },
        });
      }

      // ---- HTML ticket detail (VULNERABLE) ----
      const htmlDetailMatch = path.match(/^\/tickets\/(\d+)$/);
      if (htmlDetailMatch && method === "GET") {
        const ticketId = parseInt(htmlDetailMatch[1], 10);
        // ---------------------------------------------------------------
        // INTENTIONAL VULNERABILITY (IDOR / Broken Access Control):
        // We require login (user != null, checked above) and we let users
        // view their own ticket normally — but we do NOT verify that
        // ticket.user_id == user.id. Changing the ID in /tickets/14 to
        // /tickets/15 therefore returns another user's ticket.
        // Correct fix: add `AND t.user_id = ?` (bind user.id) or explicit
        // `if (ticket.user_id !== user.id) return 403`.
        // ---------------------------------------------------------------
        const detail = await getTicketDetail(env, ticketId);
        if (!detail) {
          return new Response(errorPage("التذكرة غير موجودة. / Ticket not found.", user, "/dashboard"), { status: 404, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        const isOwner = detail.ticket.user_id === user!.id;
        const ownerNote = isOwner
          ? `<span class="badge ok">تذكرتك / Yours</span>`
          : `<span class="badge warn">تذكرة مستخدم آخر / Another user</span>`;
        const repliesHtml =
          detail.replies.length === 0
            ? `<p class="muted">لا ردود بعد. / No replies yet.</p>`
            : detail.replies
                .map(
                  (r) => `<div class="reply${r.is_staff ? " staff" : ""}"><div class="reply-meta"><strong>${escapeHtml(r.author_name ?? "—")}</strong>${r.is_staff ? " <span class='badge'>فريق الدعم / Staff</span>" : ""} <span class="muted">${escapeHtml(r.created_at)}</span></div><p>${escapeHtml(r.body).replace(/\n/g, "<br>")}</p></div>`
                )
                .join("");
        return new Response(
          layout(
            `تذكرة #${detail.ticket.id}`,
            `<p><a href="/dashboard">← رجوع للوحة / Back to dashboard</a></p>
            <div class="card">
              <div class="row-between"><h2>#${detail.ticket.id} — ${escapeHtml(detail.ticket.title)}</h2>${ownerNote}</div>
              <p class="muted">فتحها ${escapeHtml(detail.ticket.owner_name ?? "")} بتاريخ ${escapeHtml(detail.ticket.created_at)} · تحديث ${escapeHtml(detail.ticket.updated_at)}</p>
              <p><span class="badge">${escapeHtml(detail.ticket.status)} — ${statusLabel(detail.ticket.status)}</span> <span class="badge">${escapeHtml(detail.ticket.category)}</span> <span class="badge">${escapeHtml(detail.ticket.priority)}</span></p>
              <h3>الوصف / Description</h3><p class="desc">${escapeHtml(detail.ticket.description).replace(/\n/g, "<br>")}</p>
              <div class="row"><a class="btn secondary" href="/api/tickets/${detail.ticket.id}/export">تحميل نسخة نصية / Download .txt</a><button class="btn secondary" onclick="window.print()">طباعة / Print</button></div>
            </div>
            <div class="card"><h3>الردود / Replies (${detail.replies.length})</h3>${repliesHtml}
              <h4>إضافة رد / Add reply</h4>
              <form method="POST" action="/tickets/${detail.ticket.id}/reply"><textarea name="body" required minlength="2" maxlength="2000" rows="3" placeholder="اكتب ردك هنا..."></textarea><button class="btn" type="submit">إرسال الرد / Post reply</button></form>
              <p class="muted">ملاحظة: الرد مسموح فقط لصاحب التذكرة وفريق الدعم.</p>
            </div>`,
            user
          ),
          { headers: { "Content-Type": "text/html; charset=utf-8" } }
        );
      }

      // ---- post reply (SECURE: ownership enforced — contrasts the vulnerable read) ----
      const replyMatch = path.match(/^\/tickets\/(\d+)\/reply$/);
      if (replyMatch && method === "POST") {
        const ticketId = parseInt(replyMatch[1], 10);
        const form = await request.formData();
        const body = String(form.get("body") ?? "").trim();
        if (body.length < 2 || body.length > 2000) {
          return new Response(errorPage("الرد 2-2000 حرف. / Reply 2-2000 chars.", user, `/tickets/${ticketId}`), { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        const ticket = await env.DB.prepare(`SELECT id, user_id FROM tickets WHERE id = ?`).bind(ticketId).first<{ id: number; user_id: number }>();
        if (!ticket) {
          return new Response(errorPage("التذكرة غير موجودة. / Ticket not found.", user, "/dashboard"), { status: 404, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        const isStaff = user!.email === AGENT_EMAIL;
        if (ticket.user_id !== user!.id && !isStaff) {
          return new Response(errorPage("غير مصرح: هذه ليست تذكرتك. / Forbidden: not your ticket.", user, "/dashboard"), { status: 403, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        await env.DB.prepare(`INSERT INTO replies (ticket_id, user_id, body, is_staff) VALUES (?, ?, ?, ?)`)
          .bind(ticketId, user!.id, body, isStaff ? 1 : 0)
          .run();
        await env.DB.prepare(`UPDATE tickets SET updated_at = datetime('now') WHERE id = ?`).bind(ticketId).run();
        return Response.redirect(new URL(`/tickets/${ticketId}`, url).toString(), 302);
      }

      return new Response(errorPage("الصفحة غير موجودة (404). / Not found.", user, "/"), { status: 404, headers: { "Content-Type": "text/html; charset=utf-8" } });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      return new Response(layout("خطأ", `<div class="card"><h2>خطأ داخلي / Internal error</h2><p class="err">${escapeHtml(msg)}</p></div>`, null), {
        status: 500,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
  },
};

const CSS = `
:root{--bg:#f4f6fb;--card:#fff;--ink:#1b2340;--muted:#6b7280;--brand:#1d4ed8;--brand2:#0ea5e9;--ok:#15803d;--warn:#b45309;--line:#e5e7eb}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:"Segoe UI",Tahoma,Arial,sans-serif}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 20px;background:#0f172a;color:#fff}
.brand strong{font-size:18px}.brand span{display:block;font-size:12px;color:#cbd5e1}
.topbar nav{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.topbar a{color:#fff;text-decoration:none;background:rgba(255,255,255,.12);padding:6px 12px;border-radius:8px}
.nav-user{font-size:13px;color:#e2e8f0}.linkbtn{background:none;border:0;color:#fff;cursor:pointer;font-size:14px;text-decoration:underline}
.container{max-width:920px;margin:24px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.card.narrow{max-width:520px;margin:24px auto}
.hero{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px}
.hero h1{margin:0 0 8px}.hero h1 small{color:var(--brand);font-size:18px}
.row{display:flex;gap:10px;margin:14px 0;flex-wrap:wrap}.row-between{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.btn{display:inline-block;background:var(--brand);color:#fff;padding:10px 18px;border-radius:9px;text-decoration:none;border:0;cursor:pointer}
.btn.secondary{background:#0f172a}.grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-top:16px}
.feat{border:1px solid var(--line);border-radius:10px;padding:12px;background:#f8fafc}
label{display:block;margin:10px 0;font-weight:600}input,select,textarea{width:100%;margin-top:6px;padding:10px;border:1px solid var(--line);border-radius:8px;font-size:15px}
textarea{resize:vertical}.muted{color:var(--muted)}.err{color:#b91c1c;background:#fef2f2;border:1px solid #fecaca;padding:10px;border-radius:8px}
.tbl{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden}.tbl th,.tbl td{padding:10px;border-bottom:1px solid var(--line);text-align:right;font-size:14px}.tbl th{background:#f1f5f9}
.badge{display:inline-block;background:#eef2ff;color:#3730a3;padding:3px 10px;border-radius:999px;font-size:12px;margin:2px}.badge.ok{background:#dcfce7;color:var(--ok)}.badge.warn{background:#fef3c7;color:var(--warn)}
.reply{border:1px solid var(--line);border-radius:10px;padding:12px;margin:10px 0;background:#f8fafc}.reply.staff{background:#eff6ff;border-color:#bfdbfe}
.reply-meta{font-size:13px;margin-bottom:6px}.desc{background:#f8fafc;border:1px solid var(--line);border-radius:8px;padding:12px;white-space:pre-wrap}
.inline-form{display:flex;gap:8px}.inline-form input{flex:1}.footer{text-align:center;color:var(--muted);font-size:13px;padding:24px}
.footer a{color:var(--brand)}
@media print{.topbar,.footer,.btn,form{display:none}.container{max-width:100%}}
`;
