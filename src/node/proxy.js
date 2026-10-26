// Identity-aware reverse proxy. Every request is authenticated, posture-checked and policy-evaluated
// before it is forwarded to the private app. Apps never see unauthenticated traffic.
import http from "node:http";

const json = (res, code, body, headers = {}) => { res.writeHead(code, { "content-type": "application/json", ...headers }); res.end(JSON.stringify(body, null, 2)); };
const readBody = (req) => new Promise((ok, bad) => { let b = ""; req.on("data", (c) => { b += c; if (b.length > 1e6) req.destroy(); }); req.on("end", () => ok(b)); req.on("error", bad); });
const bearer = (req) => (req.headers.authorization || "").replace(/^Bearer\s+/i, "") || /(?:^|;\s*)prism_session=([^;]+)/.exec(req.headers.cookie || "")?.[1] || "";

export function createProxy(broker, { upstreams = {}, adminKey = null, log = () => {} } = {}) {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://x"), [, first = "", ...rest] = url.pathname.split("/");
    try {
      if (url.pathname === "/healthz") return json(res, 200, { ok: true, policy: broker.policy.version, sessions: broker.sessions.size });
      if (url.pathname === "/auth/login" && req.method === "POST") {
        const b = JSON.parse((await readBody(req)) || "{}"), r = broker.login(b.user, b.device, { mfa: b.mfa !== false });
        log(`${r.ok ? "LOGIN" : "LOGIN DENIED"} ${b.user}@${b.device} posture=${r.posture.score}`);
        return r.ok ? json(res, 200, { token: r.token, sid: r.sid, posture: r.posture }, { "set-cookie": `prism_session=${r.token}; HttpOnly; Secure; SameSite=Strict; Path=/` }) : json(res, 403, { error: r.error, posture: r.posture });
      }
      if (url.pathname === "/auth/mfa" && req.method === "POST") {
        const v = broker.access(bearer(req), "__mfa__", { deviceId: req.headers["x-device-id"] }); // validates token + session
        const sid = v.sid || JSON.parse(Buffer.from(bearer(req).split(".")[1] || "", "base64url").toString() || "{}").sid;
        return broker.stepUp(sid) ? json(res, 200, { ok: true, sid }) : json(res, 401, { error: "no session" });
      }
      if (url.pathname === "/_audit") return json(res, 200, { verify: broker.verifyAudit(), entries: broker.audit.slice(-50) });
      if (url.pathname === "/_policy") {
        if (req.method === "GET") { res.writeHead(200, { "content-type": "text/plain" }); return res.end(broker.policy.src); }
        if (req.method === "PUT") { if (!adminKey || req.headers["x-admin-key"] !== adminKey) return json(res, 403, { error: "admin key required" }); try { const p = broker.setPolicy(await readBody(req)); return json(res, 200, { version: p.version, rules: p.rules.length, lint: p.lint() }); } catch (e) { return json(res, 400, { error: e.message }); } }
      }
      const app = first, target = upstreams[app];
      if (!broker.policy.apps[app]) return json(res, 404, { error: `no app ${app}` });
      const d = broker.access(bearer(req), app, { deviceId: req.headers["x-device-id"], geo: req.headers["x-geo-country"] ? { country: String(req.headers["x-geo-country"]), city: "?", lat: 0, lon: 0 } : undefined });
      log(`${d.effect.toUpperCase().padEnd(9)} ${d.user || "-"} → ${app}${d.rule ? " [" + d.rule + "]" : ""} ${d.reason || ""}`);
      const hdr = { "x-prism-decision": d.effect, "x-prism-rule": d.rule || "", "x-prism-policy": broker.policy.version };
      if (d.effect === "challenge") return json(res, 401, { error: "step-up MFA required", reason: d.reason }, { ...hdr, "www-authenticate": 'Bearer error="insufficient_user_authentication", acr_values="mfa"' });
      if (d.effect !== "allow") return json(res, d.status || 403, { error: d.status === 401 ? "unauthenticated" : "forbidden", reason: d.reason, rule: d.rule }, hdr);
      if (!target) return json(res, 200, { ok: true, app, user: d.user, route: d.route, note: "allowed; no upstream configured" }, hdr);
      const up = new URL(target), headers = { ...req.headers, host: up.host, "x-prism-user": d.user, "x-prism-session": d.sid, "x-prism-score": String(d.score), "x-forwarded-for": req.socket.remoteAddress };
      delete headers.authorization; delete headers.cookie;
      const preq = http.request({ hostname: up.hostname, port: up.port, method: req.method, path: "/" + rest.join("/") + url.search, headers }, (pres) => { res.writeHead(pres.statusCode, { ...pres.headers, ...hdr, "x-prism-route": d.route.path.join(">") }); pres.pipe(res); });
      preq.on("error", (e) => json(res, 502, { error: "upstream unreachable", detail: e.message }, hdr)); req.pipe(preq);
    } catch (e) { json(res, e.status || 500, { error: e.message }); }
  });
}
