// =============================================================================
// Lilou Books workshop board (sadnaot.liloubooks.com): server library
// -----------------------------------------------------------------------------
// • Auth: one shared password in env SADNAOT_PASSWORD. Login sets an httpOnly
//   cookie signed with a key derived from that password; changing the
//   password logs everyone out.
// • Storage: Vercel Blob, PRIVATE access. One JSON file per document:
//   data/<collection>/<id>.json, plus data/meta/settings.json. The token
//   (BLOB_READ_WRITE_TOKEN) is injected by Vercel when the store is connected.
// • Calendar: the owner pastes her Google Calendar "secret address in iCal
//   format" in Settings. Events whose title contains "סדנ" become workshops;
//   date and times follow the calendar. Sync runs when the board is opened
//   (at most every 3 minutes) and from a daily cron.
// =============================================================================

import { createHmac, createHash, timingSafeEqual } from "node:crypto";
import { put, list, get, del } from "@vercel/blob";

export const COLS = ["workshops", "inventory", "types"];
export const COOKIE = "sadnaot_s";
const SESSION_DAYS = 60;
const IMPORT_TOKEN_SHA256 = "a1f7c3e333ddc491cea3895df3ea845ade7d2c799ef0f36846cf5e197d7341d5";

// ---------------------------------------------------------------- http -----
export function send(res, status, body, extraHeaders = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}
export async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  const chunks = [];
  let size = 0;
  for await (const c of req) { size += c.length; if (size > 2_000_000) throw new Error("too big"); chunks.push(c); }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { return {}; }
}
function cookieOf(req, name) {
  const h = req.headers.cookie || "";
  for (const part of h.split(/;\s*/)) { const i = part.indexOf("="); if (part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1)); }
  return undefined;
}

// ---------------------------------------------------------------- auth -----
function key() { const p = process.env.SADNAOT_PASSWORD; return p && p.length >= 4 ? "sadnaot:" + p : null; }
const sign = (payload, k) => createHmac("sha256", k).update(payload).digest("base64url");
export const passwordConfigured = () => key() !== null;
export function checkPassword(given) {
  const p = process.env.SADNAOT_PASSWORD || "";
  const a = createHash("sha256").update(String(given)).digest();
  const b = createHash("sha256").update(p).digest();
  return p.length >= 4 && timingSafeEqual(a, b);
}
export function sessionCookie() {
  const exp = String(Date.now() + SESSION_DAYS * 864e5);
  const v = exp + "." + sign(exp, key());
  return `${COOKIE}=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_DAYS * 86400}`;
}
export const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
export function authed(req) {
  const k = key(); const c = cookieOf(req, COOKIE);
  if (!k || !c) return false;
  const [exp, sig] = c.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const want = sign(exp, k);
  return want.length === sig.length && timingSafeEqual(Buffer.from(want), Buffer.from(sig));
}
export function importTokenOk(t) {
  return typeof t === "string" && t.length >= 20 && createHash("sha256").update(t).digest("hex") === IMPORT_TOKEN_SHA256;
}

// ---------------------------------------------------------------- data -----
const ID_RE = /^[A-Za-z0-9_\-.~:@+]{1,200}$/;
export const validId = (id) => typeof id === "string" && ID_RE.test(id) && id !== "." && id !== "..";
const pathOf = (col, id) => `data/${col}/${id}.json`;

async function readJson(pathname) {
  const r = await get(pathname, { access: "private", useCache: false });
  if (!r || !r.stream) return null;
  return await new Response(r.stream).json();
}
async function writeJson(pathname, obj) {
  await put(pathname, JSON.stringify(obj), {
    access: "private", addRandomSuffix: false, allowOverwrite: true, contentType: "application/json", cacheControlMaxAge: 60,
  });
}
async function listAll(prefix) {
  const out = []; let cursor;
  do { const r = await list({ prefix, cursor, limit: 1000 }); out.push(...r.blobs); cursor = r.hasMore ? r.cursor : undefined; } while (cursor);
  return out;
}

export async function readCol(col) {
  const blobs = await listAll(`data/${col}/`);
  const docs = await Promise.all(blobs.map(async (b) => {
    const id = b.pathname.slice(`data/${col}/`.length).replace(/\.json$/, "");
    try { const d = await readJson(b.pathname); return d ? { ...d, id } : null; } catch { return null; }
  }));
  return docs.filter(Boolean);
}
export async function readSettings() { try { return (await readJson("data/meta/settings.json")) || {}; } catch { return {}; } }
async function patchSettings(patch) { const s = await readSettings(); await writeJson("data/meta/settings.json", { ...s, ...patch }); }

export async function readAll() {
  const [workshops, inventory, types, settings] = await Promise.all([readCol("workshops"), readCol("inventory"), readCol("types"), readSettings()]);
  return { workshops, inventory, types, settings: { hasIcs: !!settings.icsUrl, lastSync: settings.lastSync || null, lastSyncResult: settings.lastSyncResult || null } };
}

function clean(d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) throw new Error("bad data");
  const s = JSON.stringify(d);
  if (s.length > 200_000) throw new Error("too big");
  const o = JSON.parse(s); delete o.id; return o;
}
function deepMerge(a, b) {
  const out = { ...(a || {}) };
  for (const [k, v] of Object.entries(b)) {
    out[k] = v && typeof v === "object" && !Array.isArray(v) && out[k] && typeof out[k] === "object" && !Array.isArray(out[k]) ? deepMerge(out[k], v) : v;
  }
  return out;
}
export async function applyWrites(ops) {
  for (const o of ops) if (!COLS.includes(o.col) || !validId(o.id) || !["set", "update", "delete"].includes(o.op)) throw new Error("bad op");
  for (const o of ops) {
    const p = pathOf(o.col, o.id);
    if (o.op === "delete") { await del(p).catch(() => {}); continue; }
    if (o.op === "set") { await writeJson(p, clean(o.data)); continue; }
    let cur = null; try { cur = await readJson(p); } catch { cur = null; }
    await writeJson(p, deepMerge(cur || {}, clean(o.data)));
  }
}
export async function isEmpty() { return (await list({ prefix: "data/workshops/", limit: 1 })).blobs.length === 0; }
export async function setIcsUrl(url) {
  if (url && !/^https:\/\/calendar\.google\.com\/calendar\/ical\/[^\s]+\.ics$/.test(url)) throw new Error("bad ics");
  await patchSettings({ icsUrl: url, lastSync: null });
}

// ------------------------------------------------------------ calendar -----
const unfold = (t) => t.replace(/\r\n[ \t]/g, "").replace(/\n[ \t]/g, "").split(/\r?\n/);
const unesc = (s) => s.replace(/\\n/gi, "\n").replace(/\\,/g, ",").replace(/\\;/g, ";").replace(/\\\\/g, "\\");
const TZ = "Asia/Jerusalem";
function localParts(d) {
  const f = new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
  const p = Object.fromEntries(f.formatToParts(d).map((x) => [x.type, x.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, time: `${p.hour === "24" ? "00" : p.hour}:${p.minute}` };
}
function parseDt(v) {
  const m = v.match(/^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?$/);
  if (!m) return null;
  const date = `${m[1]}-${m[2]}-${m[3]}`;
  if (!m[4]) return { date, time: "" };
  if (m[7]) return localParts(new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6])));
  return { date, time: `${m[4]}:${m[5]}` }; // TZID local time: the calendar is in Israel time
}
export function parseIcs(txt) {
  const out = []; let cur = null;
  for (const line of unfold(txt)) {
    if (line === "BEGIN:VEVENT") { cur = {}; continue; }
    if (line === "END:VEVENT") {
      if (cur && cur.UID && cur.DTSTART && !cur["RECURRENCE-ID"]) {
        const s = parseDt(cur.DTSTART), e = cur.DTEND ? parseDt(cur.DTEND) : null;
        if (s) out.push({ uid: cur.UID.replace(/@google\.com$/, ""), summary: unesc(cur.SUMMARY || ""), date: s.date, start: s.time, end: e ? e.time : "",
          desc: unesc(cur.DESCRIPTION || ""), location: unesc(cur.LOCATION || ""), cancelled: (cur.STATUS || "").toUpperCase() === "CANCELLED" });
      }
      cur = null; continue;
    }
    if (!cur) continue;
    const i = line.indexOf(":"); if (i < 0) continue;
    cur[line.slice(0, i).split(";")[0].toUpperCase()] = line.slice(i + 1);
  }
  return out;
}
const EXCLUDE = /לקנות|בישול|שיננית|רופא/;
function guessParticipants(title, desc) {
  const m = title.match(/(\d+)\s*(?:משתתפ|אנשים|איש)/) || title.match(/פרטית\s*-?\s*(\d+)/);
  if (m) return Number(m[1]);
  const names = desc.split(/[\/\n]/).map((s) => s.trim()).filter(Boolean);
  if (!names.length || names.some((n) => n.length > 40)) return 0;
  return names.reduce((s, n) => s + (n === "+1" ? 1 : /וחבר/.test(n) ? 2 : 1), 0);
}
const safeId = (uid) => "gcal-" + uid.replace(/[^A-Za-z0-9_\-]/g, "").slice(0, 120);

export async function syncCalendar({ force = false } = {}) {
  const meta = await readSettings();
  if (!meta.icsUrl) return { ok: false, reason: "no_ics" };
  const last = meta.lastSync ? Date.parse(meta.lastSync) : 0;
  if (!force && Date.now() - last < 3 * 60_000) return { ok: true, skipped: true };
  await patchSettings({ lastSync: new Date().toISOString() });

  let txt;
  try {
    const r = await fetch(meta.icsUrl, { cache: "no-store", signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error("HTTP " + r.status);
    txt = await r.text();
  } catch (e) {
    const res = { ok: false, reason: "fetch_failed", detail: String(e).slice(0, 120), at: new Date().toISOString() };
    await patchSettings({ lastSyncResult: res });
    return res;
  }
  const today = localParts(new Date()).date;
  const from = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10);
  const events = parseIcs(txt).filter((e) => e.date >= from && /סדנ/.test(e.summary) && !EXCLUDE.test(e.summary));

  const [ws, types] = await Promise.all([readCol("workshops"), readCol("types")]);
  const byGcal = new Map(ws.filter((w) => typeof w.gcalId === "string").map((w) => [w.gcalId, w]));
  const prep = (types.find((t) => t.id === "open") || {}).prep || [];
  const ops = []; let created = 0, updated = 0, cancelled = 0; const seen = new Set();
  for (const e of events) {
    seen.add(e.uid);
    const ex = byGcal.get(e.uid);
    if (!ex) {
      if (e.cancelled) continue;
      ops.push({ op: "set", col: "workshops", id: safeId(e.uid), data: {
        title: e.summary, typeId: "open", status: e.date < today ? "done" : "confirmed", date: e.date, start: e.start, end: e.end,
        place: e.location, address: "", participants: guessParticipants(e.summary, e.desc), capacity: null, contact: "", phone: "", price: "", link: "",
        notes: (e.desc ? "מהיומן: " + e.desc.replace(/\n/g, " / ") + " · " : "") + "נוסף אוטומטית מהיומן",
        checklist: e.date < today ? [] : prep.map((t) => ({ t, d: false })), created: new Date().toISOString(), source: "gcal", gcalId: e.uid } });
      created++; continue;
    }
    const patch = {};
    if (ex.date !== e.date) patch.date = e.date;
    if (ex.start !== e.start) patch.start = e.start;
    if (e.end && ex.end !== e.end) patch.end = e.end;
    if (ex.gcalMissing) patch.gcalMissing = false;
    if (e.cancelled && ex.status !== "cancelled") { patch.status = "cancelled"; cancelled++; }
    if (Object.keys(patch).length) { ops.push({ op: "update", col: "workshops", id: ex.id, data: patch }); updated++; }
  }
  for (const [uid, ex] of byGcal) {
    if (String(ex.date || "") >= today && !seen.has(uid) && !ex.gcalMissing && ex.status !== "cancelled")
      ops.push({ op: "update", col: "workshops", id: ex.id, data: { gcalMissing: true } });
  }
  if (ops.length) await applyWrites(ops);
  const res = { ok: true, created, updated, cancelled, events: events.length, at: new Date().toISOString() };
  await patchSettings({ lastSyncResult: res });
  return res;
}
