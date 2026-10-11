// CyberShield API: connects a user's website and toggles rate limiting on it.
// Rate limiting is enforced INSIDE the user's site by cybershield-guard.js;
// this server only stores settings, so it never fetches user-supplied URLs.
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || "*" }));
app.use(express.json({ limit: "10kb" }));

const sites = new Map(); // in memory: resets on redeploy
const rnd = (n) => crypto.randomBytes(n).toString("hex");
const same = (a, b) => {
  a = Buffer.from(String(a || "")); b = Buffer.from(String(b || ""));
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
  sites.set(id, { host: u.host, ownerKey, guardKey, lastSeen: 0, protect: false, max: 60, windowSec: 60, allowed: 0, blocked: 0 });
  res.json({ siteId: id, ownerKey, guardKey, host: u.host });
});

app.get("/api/sites/:id/status", limit(60), owner, (req, res) => {
  const s = req.site;
  res.json({ connected: Date.now() - s.lastSeen < 45000, protect: s.protect, max: s.max, windowSec: s.windowSec, allowed: s.allowed, blocked: s.blocked });
});

app.post("/api/sites/:id/protect", limit(30), owner, (req, res) => {
  const s = req.site, b = req.body || {};
  s.protect = b.enabled === true;
  s.max = clamp(b.max, 5, 10000, s.max);
  s.windowSec = clamp(b.windowSec, 10, 3600, s.windowSec);
  res.json({ ok: true, protect: s.protect, max: s.max, windowSec: s.windowSec });
});

// Called by the guard on the user's server every ~15s (heartbeat + stats + settings)
app.post("/api/guard/:id/sync", limit(30), (req, res) => {
  const s = sites.get(req.params.id);
  if (!s || !same(req.headers["x-guard-key"], s.guardKey)) return res.status(403).json({ error: "forbidden" });
  const b = req.body || {};
  s.lastSeen = Date.now();
  s.allowed += clamp(b.allowed, 0, 1e9, 0);
  s.blocked += clamp(b.blocked, 0, 1e9, 0);
  res.json({ enabled: s.protect, max: s.max, windowSec: s.windowSec });
});

app.get("/cybershield-guard.js", (req, res) => res.type("js").sendFile(path.join(__dirname, "cybershield-guard.js")));
app.get("/", (req, res) => res.type("text").send("CyberShield API running"));

app.listen(process.env.PORT || 3000, () => console.log("CyberShield API up"));
        
