// CyberShield API: connects a user's website and toggles rate limiting on it.
// Two modes:
//  - "guard": rate limiting is enforced INSIDE the user's site by cybershield-guard.js
//    (Node/Express). This server only stores settings.
//  - "cloudflare": works for ANY website behind Cloudflare. The user gives a scoped
//    Cloudflare API token; this server creates/removes ONE rate limiting rule on their
//    zone. The token is stored encrypted (AES-256-GCM) and requires CF_TOKEN_SECRET.
// This server never fetches user-supplied URLs (it only talks to api.cloudflare.com).
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
 
const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || "*" }));
app.use(express.json({ limit: "64kb" }));
 
const sites = new Map();
 
// Optional persistence: free Upstash Redis over REST (no extra npm packages).
// Without UPSTASH_* variables it falls back to memory only (lost on redeploy).
const R = process.env.UPSTASH_REDIS_REST_URL, T = process.env.UPSTASH_REDIS_REST_TOKEN;
let dirty = false;
const redis = async (cmd) => {
  const r = await fetch(R, { method: "POST", headers: { Authorization: "Bearer " + T, "Content-Type": "application/json" }, body: JSON.stringify(cmd) });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
};
async function load() {
  if (!R || !T) return console.log("Persistence off (memory only)");
  try {
    const v = await redis(["GET", "cybershield:sites"]);
    if (v) for (const [k, site] of Object.entries(JSON.parse(v))) sites.set(k, site);
    console.log("Persistence on, loaded", sites.size, "sites");
  } catch (e) { console.log("Load failed:", e.message); }
}
async function save() {
  if (!R || !T || !dirty) return;
  dirty = false;
  try { await redis(["SET", "cybershield:sites", JSON.stringify(Object.fromEntries([...sites].map(([k, v]) => { const { logs, logSeq, ...rest } = v; if (rest.cf) { const { logBusy, logAt, logFrom, logOk, ...cfRest } = rest.cf; rest.cf = cfRest; } return [k, rest]; })))]); console.log("Saved", sites.size, "sites"); }
  catch (e) { dirty = true; console.log("Save failed:", e.message); }
}
setInterval(save, 10000).unref();
// Railway sends SIGTERM on redeploy: save right away so nothing is lost
process.on("SIGTERM", async () => { await save(); process.exit(0); });
const rnd = (n) => crypto.randomBytes(n).toString("hex");
const sha = (v) => crypto.createHash("sha256").update(String(v || "")).digest("hex");
// keys are stored only as SHA-256 hashes; `given` is the raw key from the request
const same = (given, storedHash) => {
  const a = Buffer.from(sha(given)), b = Buffer.from(String(storedHash || ""));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const clamp = (v, lo, hi, d) => { v = Number(v); return Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.round(v))) : d; };
 
// Rate limit this API too
const buckets = new Map();
const limit = (max) => (req, res, next) => {
  const k = req.path + "|" + req.ip, now = Date.now();
  let b = buckets.get(k);
  if (!b || b.reset < now) { b = { n: 0, reset: now + 60000 }; buckets.set(k, b); }
  if (++b.n > max) return res.status(429).json({ error: "rate_limited" });
  next();
};
setInterval(() => { const n = Date.now(); for (const [k, b] of buckets) if (b.reset < n) buckets.delete(k); }, 60000).unref();
 
// ---------------------------------------------------------------- Cloudflare mode
const CFAPI = "https://api.cloudflare.com/client/v4";
const TOKEN_KEY = process.env.CF_TOKEN_SECRET ? crypto.createHash("sha256").update(process.env.CF_TOKEN_SECRET).digest() : null;
if (!TOKEN_KEY) console.log("Cloudflare mode OFF (set CF_TOKEN_SECRET to enable it)");
const encTok = (t) => {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv("aes-256-gcm", TOKEN_KEY, iv);
  const d = Buffer.concat([c.update(t, "utf8"), c.final()]);
  return [iv, c.getAuthTag(), d].map((b) => b.toString("base64")).join(".");
};
const decTok = (s) => {
  const [iv, tag, d] = String(s).split(".").map((x) => Buffer.from(x, "base64"));
  const c = crypto.createDecipheriv("aes-256-gcm", TOKEN_KEY, iv);
  c.setAuthTag(tag);
  return Buffer.concat([c.update(d), c.final()]).toString("utf8");
};
class CfError extends Error { constructor(msg, status, code) { super(msg); this.status = status; this.code = code; } }
async function cf(token, method, p, body) {
  let r;
  try {
    r = await fetch(CFAPI + p, { method, headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(15000) });
  } catch (e) { throw new CfError("Cannot reach Cloudflare", 502, "unreachable"); }
  let j = null;
  try { j = await r.json(); } catch (e) { /* non-JSON */ }
  if (!r.ok || !j || j.success === false) {
    const e0 = j && j.errors && j.errors[0];
    throw new CfError((e0 && e0.message) || ("Cloudflare HTTP " + r.status), r.status, e0 && e0.code);
  }
  return j.result;
}
// Find the zone for a hostname (tries sub.example.com, then example.com)
async function findZone(token, hostname) {
  const parts = hostname.toLowerCase().split(".");
  for (let i = 0; i < parts.length - 1; i++) {
    const z = await cf(token, "GET", "/zones?name=" + encodeURIComponent(parts.slice(i).join(".")) + "&per_page=1");
    if (z && z.length) return z[0];
  }
  return null;
}
function planKey(z) {
  const p = (z && z.plan) || {};
  const s = ((p.legacy_id || "") + " " + (p.name || "")).toLowerCase();
  if (s.includes("enterprise")) return "enterprise";
  if (s.includes("business")) return "business";
  if (s.includes("pro")) return "pro";
  return "free"; // unknown plan: free limits are valid on every plan
}
// Cloudflare plan limits: Free = 10s period/timeout only; Pro up to 1 min; Business up to 10 min
const PERIODS = [10, 15, 20, 30, 40, 45, 60, 90, 120, 180, 240, 300, 480, 600, 900, 1200, 1800, 2400, 3600];
const PERIOD_CAP = { free: 10, pro: 60, business: 600, enterprise: 3600 };
function mapLimit(plan, max, windowSec) {
  let period = plan === "free" ? 10 : (PERIODS.filter((p) => p <= Math.min(PERIOD_CAP[plan], windowSec)).pop() || 10);
  const requests = Math.max(1, Math.round(max * period / windowSec));
  const timeout = plan === "free" ? 10 : ([10, 60, 120, 300, 600, 3600].filter((t) => t <= Math.max(period, 10)).pop() || 10);
  return { period, requests, timeout };
}
const CF_REF = "cybershield_rate_limit";
function buildRule(site, m) {
  // Free plan can only match on Path, so the rule covers the whole zone there.
  // Paid plans can match on Host, so the rule is limited to the connected hostname.
  let expression = '(http.request.uri.path contains "/")';
  const h = String(site.host || "").split(":")[0].toLowerCase();
  if (site.cf.plan !== "free" && /^[a-z0-9.-]+$/.test(h)) {
    const alt = h.startsWith("www.") ? h.slice(4) : "www." + h;
    expression = '(http.host in {"' + h + '" "' + alt + '"})';
  }
  return {
    description: "CyberShield rate limit", ref: CF_REF, expression, action: "block", enabled: true,
    ratelimit: { characteristics: ["cf.colo.id", "ip.src"], period: m.period, requests_per_period: m.requests, mitigation_timeout: m.timeout }
  };
}
// Create/update (enabled) or delete (disabled) our single rule. Returns the enforced limit or null.
async function applyCf(site, enabled, max, windowSec) {
  const token = decTok(site.cf.tokenEnc), z = site.cf.zoneId;
  let rs = null;
  try { rs = await cf(token, "GET", "/zones/" + z + "/rulesets/phases/http_ratelimit/entrypoint"); }
  catch (e) { if (e.status !== 404) throw e; }
  const mine = ((rs && rs.rules) || []).find((r) => r.ref === CF_REF);
  if (!enabled) {
    if (mine) await cf(token, "DELETE", "/zones/" + z + "/rulesets/" + rs.id + "/rules/" + mine.id);
    site.cf.ruleId = null; site.cf.enforced = null;
    return null;
  }
  const m = mapLimit(site.cf.plan, max, windowSec), rule = buildRule(site, m);
  let after;
  if (!rs) after = await cf(token, "POST", "/zones/" + z + "/rulesets", { name: "CyberShield rate limiting", kind: "zone", phase: "http_ratelimit", rules: [rule] });
  else if (mine) after = await cf(token, "PATCH", "/zones/" + z + "/rulesets/" + rs.id + "/rules/" + mine.id, rule);
  else after = await cf(token, "POST", "/zones/" + z + "/rulesets/" + rs.id + "/rules", rule);
  const got = ((after && after.rules) || []).find((r) => r.ref === CF_REF);
  site.cf.ruleId = (got && got.id) || (mine && mine.id) || null;
  site.cf.enforced = m;
  return m;
}
function cfFail(res, e) {
  if (!(e instanceof CfError)) { console.log("cf error:", e && e.message); return res.status(500).json({ error: "server_error" }); }
  const msg = String(e.message || "").toLowerCase();
  let code = "cloudflare_error";
  if (e.code === "unreachable") code = "cloudflare_unreachable";
  else if (e.status === 401 || e.status === 403) code = "cloudflare_permission";
  else if (/limit|quota|maximum|exceed/.test(msg)) code = "cloudflare_rule_limit";
  console.log("cf error:", e.status, e.code, e.message);
  res.status(code === "cloudflare_unreachable" ? 502 : 400).json({ error: code, detail: String(e.message).slice(0, 200) });
}
// Best-effort traffic counters for the last 23h (needs the token's Analytics:Read permission)
const statsBusy = new Set();
async function refreshStats(id, s) {
  if (!s.cf || !s.protect || statsBusy.has(id) || Date.now() - (s.cf.statsAt || 0) < 60000) return;
  statsBusy.add(id);
  try {
    const token = decTok(s.cf.tokenEnc), now = new Date(), since = new Date(now.getTime() - 23 * 3600 * 1000);
    const rid = /^[a-f0-9]+$/i.test(s.cf.ruleId || "") ? s.cf.ruleId : null;
    const range = 'datetime_geq:"' + since.toISOString() + '",datetime_lt:"' + now.toISOString() + '"';
    const q = '{viewer{zones(filter:{zoneTag:"' + s.cf.zoneId + '"}){' +
      'total:httpRequestsAdaptiveGroups(limit:1,filter:{' + range + '}){count}' +
      (rid ? 'blocked:firewallEventsAdaptiveGroups(limit:1,filter:{' + range + ',ruleId:"' + rid + '",action:"block"}){count}' : '') + '}}}';
    const r = await fetch(CFAPI + "/graphql", { method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ query: q }), signal: AbortSignal.timeout(15000) });
    const j = await r.json();
    const z = j && j.data && j.data.viewer && j.data.viewer.zones && j.data.viewer.zones[0];
    if (z) {
      const total = (z.total && z.total[0] && z.total[0].count) || 0;
      const blocked = (z.blocked && z.blocked[0] && z.blocked[0].count) || 0;
      s.cf.stats = { allowed: Math.max(0, total - blocked), blocked };
    } else s.cf.stats = null;
  } catch (e) { s.cf.stats = null; }
  s.cf.statsAt = Date.now();
  statsBusy.delete(id);
}

function owner(req, res, next) {
  const s = sites.get(req.params.id);
  if (!s) return res.status(404).json({ error: "not_found" });
  if (!same(req.headers["x-owner-key"], s.ownerKey)) return res.status(403).json({ error: "forbidden" });
  req.site = s; next();
}
 
app.post("/api/sites/connect", limit(10), (req, res) => {
  let u;
  try { u = new URL(String((req.body && req.body.url) || "")); } catch (e) { return res.status(400).json({ error: "invalid_url" }); }
  if (!/^https?:$/.test(u.protocol)) return res.status(400).json({ error: "invalid_url" });
  if (sites.size >= 1000) return res.status(503).json({ error: "busy" });
  const id = rnd(6), ownerKey = rnd(16), guardKey = rnd(16);
  sites.set(id, { host: u.host, ownerKey: sha(ownerKey), guardKey: sha(guardKey), lastSeen: 0, protect: false, max: 60, windowSec: 60, allowed: 0, blocked: 0 });
  dirty = true;
  res.json({ siteId: id, ownerKey, guardKey, host: u.host });
});
 
app.get("/api/sites/:id/status", limit(60), owner, (req, res) => {
  const s = req.site;
  if (s.mode === "cloudflare") {
    refreshStats(req.params.id, s);
    const st = s.cf.stats;
    return res.json({ connected: true, mode: "cloudflare", plan: s.cf.plan, zone: s.cf.zoneName, protect: s.protect, max: s.max, windowSec: s.windowSec, enforced: s.cf.enforced || null, allowed: st ? st.allowed : null, blocked: st ? st.blocked : null, statsWindow: "24h" });
  }
  res.json({ connected: Date.now() - s.lastSeen < 45000, protect: s.protect, max: s.max, windowSec: s.windowSec, allowed: s.allowed, blocked: s.blocked });
});
 
app.post("/api/sites/:id/protect", limit(30), owner, async (req, res) => {
  const s = req.site, b = req.body || {};
  if (s.mode === "cloudflare") {
    const enabled = b.enabled === true, max = clamp(b.max, 5, 10000, s.max), windowSec = clamp(b.windowSec, 10, 3600, s.windowSec);
    try {
      const m = await applyCf(s, enabled, max, windowSec);
      s.protect = enabled; s.max = max; s.windowSec = windowSec; s.cf.statsAt = 0; dirty = true;
      return res.json({ ok: true, protect: s.protect, max: s.max, windowSec: s.windowSec, enforced: m });
    } catch (e) { return cfFail(res, e); }
  }
  s.protect = b.enabled === true;
  s.max = clamp(b.max, 5, 10000, s.max);
  s.windowSec = clamp(b.windowSec, 10, 3600, s.windowSec);
  dirty = true;
  res.json({ ok: true, protect: s.protect, max: s.max, windowSec: s.windowSec });
});
 
// Connect a site via Cloudflare (works for any stack). Token is encrypted at rest and never returned.
app.post("/api/sites/connect-cloudflare", limit(6), async (req, res) => {
  if (!TOKEN_KEY) return res.status(503).json({ error: "cloudflare_unavailable" });
  const b = req.body || {};
  let u;
  try { u = new URL(String(b.url || "")); } catch (e) { return res.status(400).json({ error: "invalid_url" }); }
  if (!/^https?:$/.test(u.protocol)) return res.status(400).json({ error: "invalid_url" });
  const token = String(b.token || "").trim();
  if (!/^[A-Za-z0-9_-]{20,200}$/.test(token)) return res.status(400).json({ error: "invalid_token" });
  if (sites.size >= 1000) return res.status(503).json({ error: "busy" });
  try {
    const zone = await findZone(token, u.hostname);
    if (!zone) return res.status(404).json({ error: "zone_not_found" });
    // confirm the token can read the rate limiting ruleset (404 just means none exists yet)
    try { await cf(token, "GET", "/zones/" + zone.id + "/rulesets/phases/http_ratelimit/entrypoint"); }
    catch (e) { if (e.status !== 404) throw e; }
    const id = rnd(6), ownerKey = rnd(16), plan = planKey(zone);
    sites.set(id, { host: u.host, ownerKey: sha(ownerKey), guardKey: "", lastSeen: 0, protect: false, max: 60, windowSec: 60, allowed: 0, blocked: 0,
      mode: "cloudflare", cf: { zoneId: zone.id, zoneName: zone.name, plan, tokenEnc: encTok(token), ruleId: null, enforced: null } });
    dirty = true;
    res.json({ siteId: id, ownerKey, host: u.host, mode: "cloudflare", plan, zone: zone.name });
  } catch (e) { cfFail(res, e); }
});

// ---------------------------------------------------------------- Live logs (for the Log Analyzer)
// Each site keeps its last 500 requests in memory only (never saved to Redis, never kept after a restart).
const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const p2 = (n) => String(n).padStart(2, "0");
function logLine(ts, ip, method, p, status) {
  const d = new Date(ts);
  const when = p2(d.getUTCDate()) + "/" + MON[d.getUTCMonth()] + "/" + d.getUTCFullYear() + ":" + p2(d.getUTCHours()) + ":" + p2(d.getUTCMinutes()) + ":" + p2(d.getUTCSeconds()) + " +0000";
  return String(ip).replace(/^::ffff:/, "") + ' - - [' + when + '] "' + method + " " + p + ' HTTP/1.1" ' + status + " 0";
}
function pushLog(s, line) {
  if (!s.logs) { s.logs = []; s.logSeq = 0; }
  s.logs.push({ n: ++s.logSeq, l: line });
  if (s.logs.length > 500) s.logs.shift();
}
const cleanTxt = (v, max) => String(v == null ? "" : v).replace(/[^\x21-\x7e]/g, "").slice(0, max);
// Cloudflare: read the newest requests from Cloudflare analytics (needs the token's Analytics:Read permission).
// Cloudflare data is a little delayed, so this is "near real time", not instant.
async function pullCfLogs(s) {
  if (!s.cf || s.cf.logBusy || Date.now() - (s.cf.logAt || 0) < 8000) return;
  s.cf.logBusy = true; s.cf.logAt = Date.now();
  try {
    const token = decTok(s.cf.tokenEnc), now = new Date();
    const from = s.cf.logFrom ? new Date(s.cf.logFrom) : new Date(now.getTime() - 5 * 60000);
    const q = '{viewer{zones(filter:{zoneTag:"' + s.cf.zoneId + '"}){rows:httpRequestsAdaptive(limit:200,orderBy:[datetime_ASC],filter:{datetime_gt:"' + from.toISOString() + '",datetime_lt:"' + now.toISOString() + '"}){datetime clientIP clientRequestHTTPMethodName clientRequestPath edgeResponseStatus}}}}';
    const r = await fetch(CFAPI + "/graphql", { method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ query: q }), signal: AbortSignal.timeout(15000) });
    const j = await r.json();
    const z = j && j.data && j.data.viewer && j.data.viewer.zones && j.data.viewer.zones[0];
    if (z && z.rows) {
      s.cf.logOk = true;
      let last = s.cf.logFrom || null;
      for (const x of z.rows) {
        pushLog(s, logLine(Date.parse(x.datetime), x.clientIP, cleanTxt(x.clientRequestHTTPMethodName, 8) || "GET", cleanTxt(x.clientRequestPath, 200) || "/", clamp(x.edgeResponseStatus, 100, 599, 200)));
        last = x.datetime;
      }
      if (last) s.cf.logFrom = last;
    } else s.cf.logOk = false;
  } catch (e) { s.cf.logOk = false; }
  s.cf.logBusy = false;
}
app.get("/api/sites/:id/logs", limit(60), owner, async (req, res) => {
  const s = req.site, since = clamp(req.query.since, 0, 1e12, 0);
  if (s.mode === "cloudflare") await pullCfLogs(s);
  const all = s.logs || [];
  // if the app is behind (or the server restarted), restart from the oldest line we still have
  const rows = all.filter((x) => x.n > since).slice(-300);
  res.json({
    connected: s.mode === "cloudflare" ? true : Date.now() - s.lastSeen < 45000,
    mode: s.mode === "cloudflare" ? "cloudflare" : "guard",
    host: s.host,
    seq: s.logSeq || 0,
    lines: rows.map((x) => x.l),
    note: s.mode === "cloudflare" && s.cf.logOk === false ? "cloudflare_logs_unavailable" : null
  });
});

// Disconnect: removes our Cloudflare rule (best effort), then forgets the site and the token
app.delete("/api/sites/:id", limit(20), owner, async (req, res) => {
  const s = req.site;
  let ruleRemoved = null;
  if (s.mode === "cloudflare") {
    try { await applyCf(s, false, s.max, s.windowSec); ruleRemoved = true; } catch (e) { ruleRemoved = false; console.log("cleanup failed:", e && e.message); }
  }
  sites.delete(req.params.id); dirty = true;
  res.json({ ok: true, ruleRemoved });
});

// Called by the guard on the user's server every ~15s (heartbeat + stats + settings)
app.post("/api/guard/:id/sync", limit(30), (req, res) => {
  const s = sites.get(req.params.id);
  if (!s || !same(req.headers["x-guard-key"], s.guardKey)) return res.status(403).json({ error: "forbidden" });
  const b = req.body || {};
  s.lastSeen = Date.now();
  s.allowed += clamp(b.allowed, 0, 1e9, 0);
  s.blocked += clamp(b.blocked, 0, 1e9, 0);
  if (Array.isArray(b.events)) for (const e of b.events.slice(0, 100)) {
    if (!e || typeof e !== "object") continue;
    pushLog(s, logLine(clamp(e.t, 0, 4e12, Date.now()), cleanTxt(e.ip, 60) || "Unknown", cleanTxt(e.m, 8) || "GET", cleanTxt(e.p, 200) || "/", clamp(e.s, 100, 599, 200)));
  }
  dirty = true;
  res.json({ enabled: s.protect, max: s.max, windowSec: s.windowSec });
});
 
app.get("/cybershield-guard.js", (req, res) => res.type("js").sendFile(path.join(__dirname, "cybershield-guard.js")));
app.get("/", (req, res) => res.type("text").send("CyberShield API running"));
 
load().then(() => app.listen(process.env.PORT || 3000, () => console.log("CyberShield API up")));

                                                                                                          
