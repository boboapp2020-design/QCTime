// QC Time API — Cloudflare Pages Function, database = D1 (binding name: DB)
// Same request shapes as the old Apps Script: GET ?action=… or POST {"action": …}.
// Every action except login/ping needs "Authorization: Bearer <token>" (or ?t=<token> for photo URLs).

const R = { ADMIN: "ผู้ดูแลระบบ", QA: "QA", QC: "QC", APPR: "ผู้อนุมัติ", SALES: "ฝ่ายขาย", WH: "คลังสินค้า", PACK: "แพ็ค" };
const ALL = Object.values(R);
const CAN = {
  readQuality: ALL,
  editQuality: [R.QA, R.APPR, R.ADMIN],
  editSpec: [R.QA, R.ADMIN],
  readDispatch: [R.QC, R.QA, R.APPR, R.SALES, R.ADMIN],
  writeDispatch: [R.QC, R.QA, R.APPR, R.ADMIN],
  readCoa: [R.QA, R.APPR, R.SALES, R.ADMIN],
  writeCoa: [R.QA, R.APPR, R.SALES, R.ADMIN],
  repack: [R.PACK, R.ADMIN],
};
const SESSION_DAYS = 30;
const PBKDF2_ITER = 2000; // แพ็กเกจฟรีจำกัด CPU ~10ms ต่อคำขอ — ค่าน้อยพอให้ล็อกอินผ่าน แต่ยังเป็นรหัสแบบ salted hash
const DEFAULT_USERS = [
  ["WH01", "1234", "พนักงานคลังสินค้า", R.WH], ["QC01", "1234", "นางสุกสะหวัน จันทะวง", R.QC], ["QC02", "1234", "ท้าวพวงมะไล สุลิยะจันโท", R.QC],
  ["QC03", "1234", "นางสุงา ไชยะลาด", R.QC], ["QC04", "1234", "นางลำดวน แก้วบัวเงิน", R.QC], ["QC05", "1234", "นางสุดสะดา สีวงดาว", R.QC],
  ["QC06", "1234", "ท้าวชมมะนา ชุมพนพักดี", R.QC], ["QA01", "1234", "ท้าววงปะเสิด สีลาพม", R.QA], ["QA02", "1234", "นางอำไพพอน สุวินคำ", R.QA],
  ["QA03", "1234", "นางคำเพีด พมมะสาน", R.QA], ["AP01", "1234", "ท้าวคำตัน สอนพุกปะเสิด", R.APPR], ["AP02", "1234", "ท้าวพูโขง เข็มมะวง", R.APPR],
  ["SA01", "1234", "พนักงานฝ่ายขาย", R.SALES], ["PA01", "1234", "พนักงานแพ็ค (Repack)", R.PACK], ["admin", "9999", "ຜູ້ດູແລລະບົບ", R.ADMIN],
];

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (user TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, salt TEXT NOT NULL, hash TEXT NOT NULL, updated_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user TEXT NOT NULL, expires INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS quality (strike TEXT PRIMARY KEY, n REAL, data TEXT NOT NULL, updated_at INTEGER, updated_by TEXT)`,
  `CREATE TABLE IF NOT EXISTS specs (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT, name TEXT NOT NULL, alt TEXT, product TEXT, t TEXT NOT NULL, updated_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS dispatch (uid TEXT PRIMARY KEY, date TEXT, status TEXT, owner TEXT, data TEXT NOT NULL, updated_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS photos (uid TEXT NOT NULL, idx INTEGER NOT NULL, data TEXT NOT NULL, updated_at INTEGER, PRIMARY KEY (uid, idx))`,
  `CREATE TABLE IF NOT EXISTS coa (cert TEXT PRIMARY KEY, status TEXT, data TEXT NOT NULL, updated_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS repack (strike TEXT NOT NULL, day TEXT NOT NULL, rcode TEXT NOT NULL, by TEXT, at INTEGER, PRIMARY KEY (strike, day))`,
];

/* ---------- helpers ---------- */
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Authorization, Content-Type", "Access-Control-Allow-Methods": "GET, POST, OPTIONS" };
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...CORS } });
const fail = (error, status = 400, extra = {}) => json({ ok: false, error, ...extra }, status);
const hex = b => [...b].map(x => x.toString(16).padStart(2, "0")).join("");
const unhex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const randHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const now = () => Date.now();
const bangkokDay = () => new Date(Date.now() + 7 * 3600e3).toISOString().slice(0, 10); // วันที่ตามเวลาลาว/ไทย (GMT+7)
async function hashPass(pass, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(String(pass)), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unhex(salt), iterations: PBKDF2_ITER }, key, 256);
  return hex(new Uint8Array(bits));
}
const safeParse = s => { try { return JSON.parse(s); } catch (e) { return null; } };
const allow = (me, list) => me && list.includes(me.role);

let ready = false;
async function init(db) {
  if (ready) return;
  await db.batch(SCHEMA.map(s => db.prepare(s)));
  const c = await db.prepare("SELECT COUNT(*) AS n FROM users").first();
  if (!c || !c.n) await upsertUsers(db, DEFAULT_USERS.map(([user, pass, name, role]) => ({ user, pass, name, role, active: true })), true);
  ready = true;
}
async function upsertUsers(db, users, setPass) {
  const stmts = [];
  for (const u of users) {
    const user = String(u.user || "").trim().toLowerCase(); if (!user) continue;
    if (setPass && u.pass) {
      const salt = randHex(16), hash = await hashPass(u.pass, salt);
      stmts.push(db.prepare(`INSERT INTO users (user, name, role, active, salt, hash, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(user) DO UPDATE SET name = ?2, role = ?3, active = ?4, salt = ?5, hash = ?6, updated_at = ?7`).bind(user, u.name || user, u.role || R.QC, u.active === false ? 0 : 1, salt, hash, now()));
    } else {
      stmts.push(db.prepare("UPDATE users SET name = ?2, role = ?3, active = ?4, updated_at = ?5 WHERE user = ?1").bind(user, u.name || user, u.role || R.QC, u.active === false ? 0 : 1, now()));
    }
  }
  if (stmts.length) await db.batch(stmts);
  return stmts.length;
}
async function whoAmI(db, token) {
  if (!token) return null;
  const row = await db.prepare("SELECT u.user, u.name, u.role, u.active, s.expires FROM sessions s JOIN users u ON u.user = s.user WHERE s.token = ?1").bind(token).first();
  if (!row || row.expires < now() || !row.active) return null;
  return { user: row.user, name: row.name, role: row.role };
}
async function inChunks(db, stmts, size = 80) { for (let i = 0; i < stmts.length; i += size) await db.batch(stmts.slice(i, i + size)); }

/* ---------- status rules (who may move a record to which status) ---------- */
function dispatchAllowed(me, prev, next) {
  if (me.role === R.ADMIN) return true;
  const was = prev ? prev.status : null, to = next.status;
  if (me.role === R.QC) return (!prev || isOwner(me, prev)) && isOwner(me, next) && ["draft", "wait_check"].includes(to) && (!prev || ["draft", "returned", "wait_check"].includes(was));
  if (me.role === R.QA) return !!prev && ["wait_check", "rejected"].includes(was) && ["wait_approve", "returned"].includes(to);
  if (me.role === R.APPR) return !!prev && was === "wait_approve" && ["done", "rejected"].includes(to);
  return false;
}
const isOwner = (me, rec) => { const by = rec && rec.recordedBy; return !!by && (String(by.username || "").toLowerCase() === me.user || by.name === me.name); };
function coaAllowed(me, prev, next) {
  if (me.role === R.ADMIN) return true;
  const was = prev ? (prev.cancelled ? "cancelled" : prev.status) : null, to = next.cancelled ? "cancelled" : next.status;
  if (to === "cancelled") return false;
  if (me.role === R.SALES) return (!prev || was === "request") && to === "request";
  if (me.role === R.QA) return !!prev && was === "request" && ["request", "wait_approve"].includes(to);
  if (me.role === R.APPR) return !!prev && was === "wait_approve" && ["issued", "request"].includes(to);
  return false;
}

/* ---------- actions ---------- */
const ACTIONS = {
  async ping({ db }) {
    const n = await db.prepare("SELECT (SELECT COUNT(*) FROM quality) AS lots, (SELECT COUNT(*) FROM specs) AS specs, (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM dispatch) AS dispatch, (SELECT COUNT(*) FROM coa) AS coa").first();
    return { ok: true, service: "qc-time", db: "cloudflare-d1", counts: n, time: new Date().toISOString() };
  },
  async login({ db, body }) {
    const user = String(body.user || "").trim().toLowerCase(), pass = String(body.pass || "");
    if (!user || !pass) return { ok: false, error: "กรอกชื่อผู้ใช้และรหัสผ่าน" };
    const u = await db.prepare("SELECT * FROM users WHERE user = ?1").bind(user).first();
    if (!u) return { ok: false, error: "ไม่พบชื่อผู้ใช้นี้" };
    if (!u.active) return { ok: false, error: "บัญชีนี้ถูกปิดการใช้งาน" };
    if ((await hashPass(pass, u.salt)) !== u.hash) return { ok: false, error: "รหัสผ่านไม่ถูกต้อง" };
    const token = randHex(32);
    await db.batch([db.prepare("DELETE FROM sessions WHERE expires < ?1").bind(now()), db.prepare("INSERT INTO sessions (token, user, expires) VALUES (?1, ?2, ?3)").bind(token, u.user, now() + SESSION_DAYS * 864e5)]);
    return { ok: true, token, user: { user: u.user, name: u.name, role: u.role } };
  },
  async logout({ db, token }) { await db.prepare("DELETE FROM sessions WHERE token = ?1").bind(token).run(); return { ok: true }; },
  async me({ me }) { return { ok: true, user: me }; },
  async changePassword({ db, me, body }) {
    const u = await db.prepare("SELECT * FROM users WHERE user = ?1").bind(me.user).first();
    if ((await hashPass(String(body.oldPass || ""), u.salt)) !== u.hash) return { ok: false, error: "รหัสผ่านเดิมไม่ถูกต้อง" };
    if (String(body.newPass || "").length < 4) return { ok: false, error: "รหัสผ่านใหม่ต้องยาวอย่างน้อย 4 ตัวอักษร" };
    const salt = randHex(16), hash = await hashPass(body.newPass, salt);
    await db.prepare("UPDATE users SET salt = ?2, hash = ?3, updated_at = ?4 WHERE user = ?1").bind(me.user, salt, hash, now()).run();
    return { ok: true };
  },

  /* users (admin) */
  async listUsers({ db, me }) {
    if (me.role !== R.ADMIN) return { ok: false, error: "เฉพาะผู้ดูแลระบบ", status: 403 };
    const r = await db.prepare("SELECT user, name, role, active, updated_at FROM users ORDER BY role, user").all();
    return { ok: true, users: r.results.map(u => ({ ...u, active: !!u.active })) };
  },
  async saveUser({ db, me, body, token }) {
    if (me.role !== R.ADMIN) return { ok: false, error: "เฉพาะผู้ดูแลระบบ", status: 403 };
    const u = body.user || {}; const user = String(u.user || "").trim().toLowerCase();
    if (!/^[a-z0-9._-]{2,32}$/.test(user)) return { ok: false, error: "ชื่อผู้ใช้ใช้ได้เฉพาะ a-z 0-9 . _ - (2–32 ตัว)" };
    if (!ALL.includes(u.role)) return { ok: false, error: "บทบาทไม่ถูกต้อง" };
    const exists = await db.prepare("SELECT user FROM users WHERE user = ?1").bind(user).first();
    if (!exists && !u.pass) return { ok: false, error: "ผู้ใช้ใหม่ต้องตั้งรหัสผ่าน" };
    if (user === me.user && (u.role !== R.ADMIN || u.active === false)) return { ok: false, error: "ลดสิทธิ์หรือปิดบัญชีของตัวเองไม่ได้" };
    await upsertUsers(db, [{ ...u, user }], !!u.pass);
    if (u.pass || u.active === false) await db.prepare("DELETE FROM sessions WHERE user = ?1 AND token <> ?2").bind(user, token).run(); // บังคับล็อกอินใหม่ทุกเครื่อง ยกเว้นเครื่องที่กำลังแก้
    return { ok: true };
  },
  async deleteUser({ db, me, body }) {
    if (me.role !== R.ADMIN) return { ok: false, error: "เฉพาะผู้ดูแลระบบ", status: 403 };
    const user = String(body.user || "").toLowerCase(); if (user === me.user) return { ok: false, error: "ลบบัญชีของตัวเองไม่ได้" };
    await db.batch([db.prepare("DELETE FROM sessions WHERE user = ?1").bind(user), db.prepare("DELETE FROM users WHERE user = ?1").bind(user)]);
    return { ok: true };
  },

  /* quality + specs */
  async getQuality({ db, me }) {
    if (!allow(me, CAN.readQuality)) return { ok: false, error: "ไม่มีสิทธิ์", status: 403 };
    const [q, s] = await db.batch([db.prepare("SELECT data FROM quality ORDER BY n DESC"), db.prepare("SELECT id, code, name, alt, product, t FROM specs ORDER BY id")]);
    // ประกอบ JSON จากข้อความที่เก็บไว้ตรงๆ (ไม่ parse ทีละแถว) เพื่อไม่ให้เกินเวลา CPU ของแพ็กเกจฟรี
    const raw = `{"ok":true,"at":${now()},"rows":[${q.results.map(r => r.data).join(",")}],"specs":[${s.results.map(r => `{"id":${r.id},"code":${JSON.stringify(r.code || "")},"name":${JSON.stringify(r.name || "")},"alt":${JSON.stringify(r.alt || "")},"product":${JSON.stringify(r.product || "")},"t":${r.t || "{}"}}`).join(",")}]}`;
    return { raw };
  },
  async saveLot({ db, me, body }) {
    if (!allow(me, CAN.editQuality)) return { ok: false, error: "ไม่มีสิทธิ์แก้ไขคุณภาพ", status: 403 };
    const row = { ...(body.row || {}) }; delete row.pending; const strike = String(row.strike || "").trim(); const key = String(row._k || strike).trim(); // _k แยก Lot ที่เลข Strike ซ้ำกัน
    if (!strike) return { ok: false, error: "ไม่มีเลข Strike" };
    const n = Number(row.strikeN ?? strike); row.strike = strike;
    await db.prepare("INSERT INTO quality (strike, n, data, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(strike) DO UPDATE SET n = ?2, data = ?3, updated_at = ?4, updated_by = ?5")
      .bind(key, isFinite(n) ? n : null, JSON.stringify({ ...row, _k: key }), now(), me.user).run();
    return { ok: true };
  },
  async saveSpec({ db, me, body }) {
    if (!allow(me, CAN.editSpec)) return { ok: false, error: "ไม่มีสิทธิ์แก้ไขสเปค", status: 403 };
    const s = body.spec || {}; if (!String(s.name || "").trim()) return { ok: false, error: "กรอกชื่อลูกค้า" };
    const vals = [s.code || "", s.name.trim(), s.alt || "", s.product || "", JSON.stringify(s.t || {}), now()];
    if (s.id) await db.prepare("UPDATE specs SET code = ?1, name = ?2, alt = ?3, product = ?4, t = ?5, updated_at = ?6 WHERE id = ?7").bind(...vals, s.id).run();
    else await db.prepare("INSERT INTO specs (code, name, alt, product, t, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)").bind(...vals).run();
    return { ok: true };
  },
  async deleteSpec({ db, me, body }) {
    if (!allow(me, CAN.editSpec)) return { ok: false, error: "ไม่มีสิทธิ์แก้ไขสเปค", status: 403 };
    await db.prepare("DELETE FROM specs WHERE id = ?1").bind(body.id).run(); return { ok: true };
  },

  /* dispatch (จ่ายออกน้ำตาล) */
  async getDispatch({ db, me, token, origin }) {
    if (!allow(me, CAN.readDispatch)) return { ok: false, error: "ไม่มีสิทธิ์", status: 403 };
    const [d, p] = await db.batch([db.prepare("SELECT data FROM dispatch ORDER BY date DESC"), db.prepare("SELECT uid, idx FROM photos ORDER BY uid, idx")]);
    const ph = {}; p.results.forEach(r => (ph[r.uid] = ph[r.uid] || []).push(`${origin}/api/photo?uid=${encodeURIComponent(r.uid)}&i=${r.idx}&t=${token}`));
    return { ok: true, records: d.results.map(r => { const rec = safeParse(r.data); if (rec && ph[rec.uid]) rec.photoUrls = ph[rec.uid]; return rec; }).filter(Boolean) };
  },
  async saveDispatch({ db, me, body }) {
    if (!allow(me, CAN.writeDispatch)) return { ok: false, error: "ไม่มีสิทธิ์", status: 403 };
    const rec = body.record || {}; if (!rec.uid) return { ok: false, error: "ไม่มี uid" };
    delete rec.photos; delete rec.photoUrls;
    const prevRow = await db.prepare("SELECT data FROM dispatch WHERE uid = ?1").bind(rec.uid).first(); const prev = prevRow ? safeParse(prevRow.data) : null;
    if (!dispatchAllowed(me, prev, rec)) return { ok: false, error: "ไม่มีสิทธิ์เปลี่ยนสถานะใบนี้", status: 403 };
    await db.prepare("INSERT INTO dispatch (uid, date, status, owner, data, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(uid) DO UPDATE SET date = ?2, status = ?3, owner = ?4, data = ?5, updated_at = ?6")
      .bind(rec.uid, rec.date || "", rec.status || "", String((rec.recordedBy && rec.recordedBy.username) || "").toLowerCase(), JSON.stringify(rec), now()).run();
    return { ok: true, updated: !!prev };
  },
  async deleteDispatch({ db, me, body }) {
    const row = await db.prepare("SELECT data FROM dispatch WHERE uid = ?1").bind(body.uid).first(); const rec = row ? safeParse(row.data) : null;
    if (rec && !(me.role === R.ADMIN || (rec.status === "draft" && isOwner(me, rec)))) return { ok: false, error: "ลบได้เฉพาะผู้ดูแลระบบ หรือร่างของตัวเอง", status: 403 };
    await db.batch([db.prepare("DELETE FROM dispatch WHERE uid = ?1").bind(body.uid), db.prepare("DELETE FROM photos WHERE uid = ?1").bind(body.uid)]);
    return { ok: true };
  },
  async savePhoto({ db, me, body, token, origin }) {
    if (!allow(me, CAN.writeDispatch)) return { ok: false, error: "ไม่มีสิทธิ์", status: 403 };
    const data = String(body.dataUrl || ""); if (!/^data:image\/(jpeg|png|webp);base64,/.test(data)) return { ok: false, error: "รูปไม่ถูกต้อง" };
    if (data.length > 1900000) return { ok: false, error: "รูปใหญ่เกินไป" };
    await db.prepare("INSERT INTO photos (uid, idx, data, updated_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(uid, idx) DO UPDATE SET data = ?3, updated_at = ?4").bind(String(body.uid), Number(body.index) || 0, data, now()).run();
    return { ok: true, url: `${origin}/api/photo?uid=${encodeURIComponent(body.uid)}&i=${Number(body.index) || 0}&t=${token}` };
  },
  async clearDispatch({ db, me }) {
    if (me.role !== R.ADMIN) return { ok: false, error: "เฉพาะผู้ดูแลระบบ", status: 403 };
    const n = await db.prepare("SELECT COUNT(*) AS n FROM dispatch").first();
    await db.batch([db.prepare("DELETE FROM dispatch"), db.prepare("DELETE FROM photos")]); return { ok: true, cleared: n.n };
  },

  /* COA */
  async getCoa({ db, me }) {
    if (!allow(me, CAN.readCoa)) return { ok: false, error: "ไม่มีสิทธิ์", status: 403 };
    const r = await db.prepare("SELECT data FROM coa ORDER BY updated_at DESC").all();
    return { ok: true, records: r.results.map(x => safeParse(x.data)).filter(Boolean) };
  },
  async saveCoa({ db, me, body }) {
    if (!allow(me, CAN.writeCoa)) return { ok: false, error: "ไม่มีสิทธิ์", status: 403 };
    const rec = body.record || {}; if (!rec.certNo) return { ok: false, error: "ไม่มีเลขที่ใบ" };
    const prevRow = await db.prepare("SELECT data FROM coa WHERE cert = ?1").bind(rec.certNo).first(); const prev = prevRow ? safeParse(prevRow.data) : null;
    if (!coaAllowed(me, prev, rec)) return { ok: false, error: "ไม่มีสิทธิ์เปลี่ยนสถานะใบนี้", status: 403 };
    await db.prepare("INSERT INTO coa (cert, status, data, updated_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(cert) DO UPDATE SET status = ?2, data = ?3, updated_at = ?4")
      .bind(rec.certNo, rec.cancelled ? "cancelled" : rec.status || "", JSON.stringify(rec), now()).run();
    return { ok: true };
  },
  async deleteCoa({ db, me, body }) {
    if (me.role !== R.ADMIN) return { ok: false, error: "เฉพาะผู้ดูแลระบบ", status: 403 };
    const r = await db.prepare("DELETE FROM coa WHERE cert = ?1").bind(body.certNo).run(); return { ok: true, deleted: r.meta.changes };
  },
  async clearCoa({ db, me }) {
    if (me.role !== R.ADMIN) return { ok: false, error: "เฉพาะผู้ดูแลระบบ", status: 403 };
    const n = await db.prepare("SELECT COUNT(*) AS n FROM coa").first(); await db.prepare("DELETE FROM coa").run(); return { ok: true, cleared: n.n };
  },

  /* Repack */
  async getRepack({ db, me, body }) {
    if (!allow(me, CAN.repack)) return { ok: false, error: "ไม่มีสิทธิ์", status: 403 };
    const r = await db.prepare("SELECT day, rcode FROM repack WHERE strike = ?1 ORDER BY day").bind(String(body.strike || "")).all();
    return { ok: true, found: true, records: r.results.map(x => ({ value: x.rcode, date: x.day })) };
  },
  async saveRepack({ db, me, body }) {
    if (!allow(me, CAN.repack)) return { ok: false, error: "ไม่มีสิทธิ์", status: 403 };
    const strike = String(body.strike || "").trim(), rcode = String(body.rcode || "").trim(), day = bangkokDay();
    if (!strike || !/^R\d{5}$/.test(rcode)) return { ok: false, error: "ข้อมูลไม่ครบ" };
    const lot = await db.prepare("SELECT strike FROM quality WHERE strike = ?1").bind(strike).first(); if (!lot) return { ok: false, error: "ไม่พบ Lot " + strike };
    const dup = await db.prepare("SELECT rcode FROM repack WHERE strike = ?1 AND day = ?2").bind(strike, day).first();
    if (dup) return { ok: false, duplicate: true, error: "วันนี้บันทึก Lot " + strike + " ไปแล้ว" };
    await db.prepare("INSERT INTO repack (strike, day, rcode, by, at) VALUES (?1, ?2, ?3, ?4, ?5)").bind(strike, day, rcode, me.user, now()).run();
    return { ok: true, value: rcode, date: day };
  },

  async deleteRepack({ db, me, body }) {
    if (me.role !== R.ADMIN) return { ok: false, error: "เฉพาะผู้ดูแลระบบ", status: 403 };
    const r = await db.prepare("DELETE FROM repack WHERE strike = ?1 AND day = ?2").bind(String(body.strike || ""), String(body.day || "")).run(); return { ok: true, deleted: r.meta.changes };
  },

  /* one-time import from Google Sheets (admin). Each part is optional; "replace" wipes that table first. */
  async importData({ db, me, body }) {
    if (me.role !== R.ADMIN) return { ok: false, error: "เฉพาะผู้ดูแลระบบ", status: 403 };
    const out = {}; const t = now();
    if (Array.isArray(body.quality)) {
      const st = body.replace ? [db.prepare("DELETE FROM quality")] : [];
      body.quality.forEach(row => { const s = String(row._k || row.strike || "").trim(); if (!s) return; const n = Number(row.strikeN ?? row.strike);
        st.push(db.prepare("INSERT INTO quality (strike, n, data, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(strike) DO UPDATE SET n = ?2, data = ?3, updated_at = ?4").bind(s, isFinite(n) ? n : null, JSON.stringify({ ...row, _k: s }), t, "import")); });
      await inChunks(db, st); out.quality = body.quality.length;
    }
    if (Array.isArray(body.specs)) {
      const st = [db.prepare("DELETE FROM specs")];
      body.specs.forEach(s => st.push(db.prepare("INSERT INTO specs (code, name, alt, product, t, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)").bind(s.code || "", s.name || "", s.alt || "", s.product || "", JSON.stringify(s.t || {}), t)));
      await inChunks(db, st); out.specs = body.specs.length;
    }
    if (Array.isArray(body.users)) out.users = await upsertUsers(db, body.users.filter(u => u.user && u.pass), true);
    if (Array.isArray(body.dispatch)) {
      const st = body.dispatch.filter(r => r && r.uid).map(r => { delete r.photos; delete r.photoUrls; return db.prepare("INSERT OR REPLACE INTO dispatch (uid, date, status, owner, data, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)").bind(r.uid, r.date || "", r.status || "", String((r.recordedBy && r.recordedBy.username) || "").toLowerCase(), JSON.stringify(r), t); });
      await inChunks(db, st); out.dispatch = st.length;
    }
    if (Array.isArray(body.coa)) {
      const st = body.coa.filter(r => r && r.certNo).map(r => db.prepare("INSERT OR REPLACE INTO coa (cert, status, data, updated_at) VALUES (?1, ?2, ?3, ?4)").bind(r.certNo, r.cancelled ? "cancelled" : r.status || "", JSON.stringify(r), r.ts || t));
      await inChunks(db, st); out.coa = st.length;
    }
    if (Array.isArray(body.repack)) {
      const st = body.repack.filter(r => r.strike && r.day && r.rcode).map(r => db.prepare("INSERT OR REPLACE INTO repack (strike, day, rcode, by, at) VALUES (?1, ?2, ?3, ?4, ?5)").bind(String(r.strike), r.day, r.rcode, "import", t));
      await inChunks(db, st); out.repack = st.length;
    }
    return { ok: true, imported: out };
  },
};
const PUBLIC = new Set(["ping", "login"]);

/* ---------- entry ---------- */
export async function onRequest(ctx) {
  const { request, env } = ctx;
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  const db = env.DB; if (!db) return fail("ยังไม่ได้ผูกฐานข้อมูล D1 (binding: DB)", 500);
  try {
    await init(db);
    const url = new URL(request.url); const origin = url.origin;
    const auth = request.headers.get("Authorization") || ""; const token = auth.startsWith("Bearer ") ? auth.slice(7) : (url.searchParams.get("t") || "");

    // photo bytes for <img src> (token in the query string)
    if (url.pathname.endsWith("/api/photo")) {
      const me = await whoAmI(db, token); if (!allow(me, CAN.readDispatch)) return new Response("forbidden", { status: 403, headers: CORS });
      const p = await db.prepare("SELECT data FROM photos WHERE uid = ?1 AND idx = ?2").bind(url.searchParams.get("uid"), Number(url.searchParams.get("i")) || 0).first();
      if (!p) return new Response("not found", { status: 404, headers: CORS });
      const [head, b64] = p.data.split(","); const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      return new Response(bin, { headers: { "Content-Type": (head.match(/image\/\w+/) || ["image/jpeg"])[0], "Cache-Control": "private, max-age=86400", ...CORS } });
    }

    let body = {};
    if (request.method === "POST") { body = safeParse(await request.text()) || {}; }
    else url.searchParams.forEach((v, k) => { body[k] = v; });
    const action = body.action || "ping"; const fn = ACTIONS[action];
    if (!fn) return fail("unknown action: " + action);
    let me = null;
    if (!PUBLIC.has(action)) { me = await whoAmI(db, token); if (!me) return fail("กรุณาเข้าสู่ระบบใหม่", 401, { auth: false }); }
    const res = await fn({ db, me, body, token, origin });
    if (res.raw) return new Response(res.raw, { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...CORS } });
    const status = res.status || 200; delete res.status;
    return json(res, status);
  } catch (e) {
    return fail(String(e && e.message || e), 500);
  }
}
