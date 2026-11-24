// /api/<action>: login, logout, data, write, settings, sync, cron, import.
// See api/_lib.js.
import {
  send, readBody, authed, passwordConfigured, checkPassword, sessionCookie, clearCookie,
  readAll, applyWrites, setIcsUrl, syncCalendar, importTokenOk, isEmpty,
} from "./_lib.js";

const fails = new Map();
const ipOf = (req) => String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";

export default async function handler(req, res) {
  const action = String((req.query && req.query.action) || new URL(req.url, "http://x").pathname.split("/").pop());
  try {
    if (req.method === "GET") {
      if (action === "cron") {
        const secret = process.env.CRON_SECRET;
        if (secret && req.headers.authorization !== `Bearer ${secret}`) return send(res, 401, { error: "no" });
        return send(res, 200, await syncCalendar({ force: true }));
      }
      if (action === "data") {
        if (!passwordConfigured()) return send(res, 503, { error: "not_configured" });
        if (!authed(req)) return send(res, 401, { error: "login" });
        try { await syncCalendar(); } catch (e) { console.error("sync", e); }
        return send(res, 200, await readAll());
      }
      return send(res, 404, { error: "not found" });
    }
    if (req.method !== "POST") return send(res, 405, { error: "method" });
    const body = await readBody(req);

    if (action === "login") {
      if (!passwordConfigured()) return send(res, 503, { error: "not_configured" });
      const ip = ipOf(req), f = fails.get(ip);
      if (f && f.until > Date.now()) return send(res, 429, { error: "wait" });
      if (!checkPassword(body.password || "")) {
        const n = (f?.n || 0) + 1;
        fails.set(ip, { n, until: n >= 5 ? Date.now() + 5 * 60_000 : 0 });
        return send(res, 401, { error: "wrong" });
      }
      fails.delete(ip);
      return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie() });
    }
    if (action === "logout") return send(res, 200, { ok: true }, { "Set-Cookie": clearCookie() });
    if (action === "import") {
      if (!importTokenOk(body.token)) return send(res, 401, { error: "no" });
      if (!(await isEmpty())) return send(res, 409, { error: "not_empty" });
      const ops = [];
      for (const col of ["workshops", "inventory", "types"]) for (const d of body.data?.[col] || []) ops.push({ op: "set", col, id: String(d.id), data: d });
      await applyWrites(ops);
      return send(res, 200, { ok: true, count: ops.length });
    }

    if (!authed(req)) return send(res, 401, { error: "login" });
    const origin = req.headers.origin;
    if (origin && origin !== "https://sadnaot.liloubooks.com" && !/^https:\/\/sadnaot[a-z0-9-]*\.vercel\.app$/.test(origin))
      return send(res, 403, { error: "origin" });

    if (action === "write") {
      const ops = body.ops;
      if (!Array.isArray(ops) || !ops.length || ops.length > 50) return send(res, 400, { error: "bad" });
      try { await applyWrites(ops); } catch (e) { return send(res, 400, { error: String(e.message) }); }
      return send(res, 200, { ok: true });
    }
    if (action === "settings") {
      try { await setIcsUrl(String(body.icsUrl || "").trim()); } catch { return send(res, 400, { error: "bad_ics" }); }
      return send(res, 200, await syncCalendar({ force: true }));
    }
    if (action === "sync") return send(res, 200, await syncCalendar({ force: true }));
    return send(res, 404, { error: "not found" });
  } catch (e) {
    console.error(action, e);
    return send(res, 500, { error: "server" });
  }
}
