// CyberShield Guard: drop-in rate limiting for Express (Node 18+, no dependencies).
// Stays OFF until the owner clicks "Add security / rate limiting" in CyberShield.
module.exports = function cybershieldGuard({ siteId, guardKey, api }) {
  let cfg = { enabled: false, max: 60, windowSec: 60 };
  let allowed = 0, blocked = 0;
  const hits = new Map();

  async function sync() {
    const a = allowed, b = blocked;
    try {
      const r = await fetch(api + "/api/guard/" + siteId + "/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-guard-key": guardKey },
        body: JSON.stringify({ allowed: a, blocked: b })
      });
      if (r.ok) { cfg = await r.json(); allowed -= a; blocked -= b; }
    } catch (e) { /* keep last settings; retry next cycle */ }
  }
  sync();
  setInterval(sync, 15000).unref();
  setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.reset < n) hits.delete(k); }, 60000).unref();

  return function (req, res, next) {
    if (!cfg.enabled) { allowed++; return next(); }
    const ip = req.ip, now = Date.now();
    let h = hits.get(ip);
    if (!h || h.reset < now) { h = { count: 0, reset: now + cfg.windowSec * 1000 }; hits.set(ip, h); }
    if (++h.count > cfg.max) {
      blocked++;
      res.set("Retry-After", String(Math.ceil((h.reset - now) / 1000)));
      return res.status(429).json({ error: "Too many requests", protectedBy: "CyberShield" });
    }
    allowed++; next();
  };
};
