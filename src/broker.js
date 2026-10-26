// The ZTNA broker: authenticates sessions, re-checks posture on every request (continuous verification),
// evaluates policy, picks a route through the mesh and writes a hash-chained audit log.
import { Policy } from "./policy.js";
import { posture } from "./posture.js";
import { Keyring, sign, verify, deviceThumb } from "./token.js";
import { Mesh } from "./mesh.js";
import { sha256 } from "./lib/sha256.js";

export class Broker {
  constructor({ policy, directory, mesh, ring = new Keyring(), ttl = 3600, minScore = 50, now = () => Date.now() / 1000 } = {}) {
    this.policy = policy instanceof Policy ? policy : new Policy(policy);
    this.dir = directory; this.mesh = mesh || new Mesh(); this.ring = ring; this.ttl = ttl; this.minScore = minScore; this.now = now;
    this.sessions = new Map(); this.audit = []; this.head = "0".repeat(64); this.seq = 0; this.subs = [];
    this.stats = { allow: 0, deny: 0, challenge: 0, revoked: 0, logins: 0 };
  }
  on(fn) { this.subs.push(fn); return this; }
  emit(e) { for (const f of this.subs) f(e); }
  setPolicy(src) { const p = new Policy(src); this.policy = p; this.emit({ type: "policy", version: p.version }); return p; }
  user(id) { const u = this.dir.users[id]; if (!u) throw Object.assign(new Error(`unknown user ${id}`), { status: 401 }); return u; }
  device(id) { const d = this.dir.devices[id]; if (!d) throw Object.assign(new Error(`unknown device ${id}`), { status: 401 }); return d; }

  // Identity comes from the IdP (here: the directory). The token binds user + device + session.
  login(userId, deviceId, { mfa = true, geo } = {}) {
    const u = this.user(userId), d = this.device(deviceId); if (d.owner !== userId) throw Object.assign(new Error(`${deviceId} is not registered to ${userId}`), { status: 403 });
    const p = posture(d), now = this.now();
    if (p.score < this.minScore) { this.log({ kind: "login", user: userId, device: deviceId, effect: "deny", reason: `posture ${p.score} < ${this.minScore}` }); this.stats.deny++; return { ok: false, error: `device posture ${p.score} below ${this.minScore}`, posture: p }; }
    const sid = "s_" + sha256(`${userId}:${deviceId}:${now}:${this.seq}`).slice(0, 12);
    const token = sign({ sub: userId, sid, aud: "prism-ztna", iat: Math.floor(now), exp: Math.floor(now + this.ttl), cnf: { dev: deviceThumb(deviceId) }, ps: p.score }, this.ring);
    this.sessions.set(sid, { sid, user: userId, device: deviceId, created: now, mfaAt: mfa ? now : null, geo: geo || u.home, requests: 0, last: now });
    this.stats.logins++; this.log({ kind: "login", user: userId, device: deviceId, effect: "allow", sid, score: p.score }); this.emit({ type: "login", sid, user: userId });
    return { ok: true, token, sid, posture: p };
  }
  stepUp(sid) { const s = this.sessions.get(sid); if (s) { s.mfaAt = this.now(); this.log({ kind: "mfa", sid, user: s.user, effect: "allow" }); } return !!s; }
  revoke(sid, reason = "revoked") { const s = this.sessions.get(sid); if (!s) return false; this.sessions.delete(sid); this.stats.revoked++; this.log({ kind: "revoke", sid, user: s.user, device: s.device, reason }); this.emit({ type: "revoke", sid, user: s.user, reason }); return true; }
  revokeDevice(deviceId, reason) { let n = 0; for (const s of [...this.sessions.values()]) if (s.device === deviceId) n += this.revoke(s.sid, reason); return n; }

  // Every request: verify token -> session alive -> fresh posture -> policy -> route.
  access(token, app, { deviceId, geo, hour } = {}) {
    const now = this.now(), v = verify(token, this.ring, { now, device: deviceId });
    const out = (effect, extra) => { this.stats[effect === "error" ? "deny" : effect]++; const rec = { kind: "access", app, effect: effect === "error" ? "deny" : effect, ...extra }; this.log(rec); this.emit({ type: "decision", ...rec }); return rec; };
    if (!v.ok) return out("error", { status: 401, reason: "token: " + v.error, user: v.claims?.sub });
    const s = this.sessions.get(v.claims.sid); if (!s) return out("error", { status: 401, reason: "session revoked", user: v.claims.sub });
    const p = posture(this.device(s.device)), g = geo || s.geo;
    if (p.score < this.minScore) { this.revoke(s.sid, `posture dropped to ${p.score}`); return out("error", { status: 401, reason: `posture dropped to ${p.score}: session revoked`, user: s.user, score: p.score }); }
    const ctx = this.context(s, { geo, hour, now });
    const dec = this.policy.decide(ctx, app); s.requests++; s.last = now;
    if (dec.effect !== "allow") return out(dec.effect, { status: dec.effect === "challenge" ? 401 : 403, rule: dec.rule, reason: dec.reasons.join("; "), user: s.user, sid: s.sid, score: p.score, trace: dec.trace });
    const r = this.mesh.route(g, app);
    if (!r.ok) return out("deny", { status: 503, rule: dec.rule, reason: r.error, user: s.user, sid: s.sid });
    return out("allow", { status: 200, rule: dec.rule, reason: dec.reasons.join("; "), user: s.user, sid: s.sid, score: p.score, route: r, trace: dec.trace, upstream: this.policy.apps[app]?.host });
  }

  // Attribute context the policy sees for a session (also used for what-if explanations).
  context(s, { geo, hour, now = this.now() } = {}) {
    const u = this.user(s.user), d = this.device(s.device), p = posture(d), g = geo || s.geo;
    return {
      user: { id: u.id, email: u.email, groups: u.groups, type: u.type, dept: u.dept },
      device: { id: d.id, os: d.os, managed: !!d.managed, score: p.score, tier: p.tier, jailbroken: !!d.jailbroken },
      geo: { country: g.country, city: g.city }, time: { hour: hour ?? new Date(now * 1000).getUTCHours() },
      mfa: { age: s.mfaAt == null ? Infinity : now - s.mfaAt }, session: { age: now - s.created, requests: s.requests },
    };
  }
  // What-if: evaluate policy for a user without logging or touching counters.
  explain(userId, app, { deviceId, geo, hour } = {}) {
    const s = [...this.sessions.values()].find((x) => x.user === userId) || { user: userId, device: deviceId, created: this.now(), mfaAt: null, geo: this.user(userId).home, requests: 0 };
    if (deviceId) s.device = deviceId; if (!s.device) s.device = Object.values(this.dir.devices).find((d) => d.owner === userId)?.id;
    const ctx = this.context(s, { geo, hour }); return { ctx, session: !!s.sid, ...this.policy.decide(ctx, app) };
  }
  // Tamper-evident audit trail: each entry commits to the previous hash.
  log(e) {
    const entry = { seq: ++this.seq, ts: +this.now().toFixed(3), policy: this.policy.version, ...e }; delete entry.trace;
    entry.prev = this.head; entry.hash = sha256(this.head + JSON.stringify({ ...entry, hash: undefined })); this.head = entry.hash;
    this.audit.push(entry); if (this.audit.length > 5000) this.audit.splice(0, 1000);
    return entry;
  }
  verifyAudit(entries = this.audit) {
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i]; if (i > 0 && e.prev !== entries[i - 1].hash) return { ok: false, at: e.seq, error: "broken chain" };
      if (sha256(e.prev + JSON.stringify({ ...e, hash: undefined })) !== e.hash) return { ok: false, at: e.seq, error: "entry modified" };
    }
    return { ok: true, entries: entries.length, head: entries.at(-1)?.hash };
  }
}
