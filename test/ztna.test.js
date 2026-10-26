import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Policy, PolicyError, tokenize, posture, Keyring, sign, verify, decode, deviceThumb, Mesh, Broker, POLICY, DIRECTORY, CONNECTORS, deviceOf } from "../src/index.js";
import { createProxy } from "../src/node/proxy.js";

const mk = (t = { v: 1e6 }) => new Broker({ policy: POLICY, directory: structuredClone(DIRECTORY), mesh: new Mesh({ connectors: CONNECTORS }), now: () => t.v });
const ctx = (o = {}) => ({ user: { groups: [], type: "employee", ...o.user }, device: { score: 90, tier: "trusted", managed: true, ...o.device }, geo: { country: "IN", ...o.geo }, time: { hour: 12 }, mfa: { age: 60 }, ...o.rest });

test("tokenizer: strings, durations, paths and operators", () => {
  const t = tokenize(`allow "x" tag:prod when user.groups != [] and mfa.age <= 15m`).map((k) => k.v ?? k.t);
  assert.deepEqual(t, ["allow", "x", "tag:prod", "when", "user.groups", "!=", "[", "]", "and", "mfa.age", "<=", 900, "eof"]);
  assert.throws(() => tokenize(`allow "oops`), PolicyError);
});
test("parser: precedence, apps, targets, require mfa, errors carry line:col", () => {
  const p = new Policy(`app a host "h:1" tags [x, y]\nallow "r" a, tag:y when not device.jailbroken and "eng" in user.groups or user.type == "admin" require mfa within 1h`);
  assert.deepEqual(p.apps.a, { name: "a", host: "h:1", tags: ["x", "y"] });
  const r = p.rules[0]; assert.equal(r.when.k, "or"); assert.equal(r.when.l.k, "and"); assert.equal(r.mfa, 3600); assert.deepEqual(r.targets, ["a", "tag:y"]);
  assert.throws(() => new Policy(`app a\nallow "x" a when user.type ==`), (e) => e instanceof PolicyError && e.line === 2);
  assert.throws(() => new Policy(`permit x`), /expected app, allow or deny/);
});
test("deny overrides allow, first allow wins, default deny explains failures", () => {
  const p = new Policy(`app db tags [prod]\ndeny "geo" * when geo.country in ["KP"]\nallow "sre" tag:prod when "sre" in user.groups\nallow "all" db`);
  assert.equal(p.decide(ctx({ user: { groups: ["sre"] }, geo: { country: "KP" } }), "db").rule, "geo");
  assert.equal(p.decide(ctx({ user: { groups: ["sre"] } }), "db").rule, "sre");
  const q = new Policy(`app db\nallow "sre" db when "sre" in user.groups and device.score >= 80`), d = q.decide(ctx({ device: { score: 40 } }), "db");
  assert.equal(d.effect, "deny"); assert.equal(d.rule, "default-deny"); assert.match(d.reasons.join(), /"sre" in user.groups/);
  assert.equal(q.decide(ctx(), "nope").effect, "deny");
});
test("operators: in (list + membership), matches glob, comparisons, bare paths", () => {
  const p = new Policy(`app a\nallow "r" a when user.email matches "*@prism.dev" and device.os in ["macos", "linux"] and device.managed and time.hour < 20`);
  assert.equal(p.decide({ ...ctx(), user: { email: "riya@prism.dev" }, device: { os: "linux", managed: true }, time: { hour: 9 } }, "a").effect, "allow");
  assert.equal(p.decide({ ...ctx(), user: { email: "x@evil.io" }, device: { os: "linux", managed: true }, time: { hour: 9 } }, "a").effect, "deny");
  assert.equal(p.decide({ ...ctx(), user: { email: "riya@prism.dev" }, device: { os: "linux", managed: false }, time: { hour: 9 } }, "a").effect, "deny");
});
test("step-up MFA: rule matches but mfa too old -> challenge", () => {
  const p = new Policy(`app db\nallow "r" db when true require mfa within 10m`);
  assert.equal(p.decide({ ...ctx(), mfa: { age: 120 } }, "db").effect, "allow");
  assert.equal(p.decide({ ...ctx(), mfa: { age: 1200 } }, "db").effect, "challenge");
});
test("lint finds unknown targets, empty tags, unprotected and unreachable apps", () => {
  const w = new Policy(readFileSync("examples/lint-me.ztna", "utf8")).lint().map((x) => x.msg).join("\n");
  assert.match(w, /wikki is not a declared app/); assert.match(w, /no app has tag:secret/); assert.match(w, /unconditional allow/); assert.match(w, /vault has no allow rule/);
  assert.deepEqual(new Policy(readFileSync("examples/policy.ztna", "utf8")).lint(), []);
});
test("posture scoring: weights, partial patch credit, jailbreak cap", () => {
  assert.equal(posture(DIRECTORY.devices["mbp-riya"]).score, 100);
  const a = posture(DIRECTORY.devices["tp-arjun"]); assert.equal(a.tier, "limited"); assert.deepEqual(a.failed, ["patch", "firewall", "lock"]);
  assert.equal(posture({ ...DIRECTORY.devices["mbp-riya"], patchAgeDays: 60 }).score, 93);
  assert.equal(posture({ ...DIRECTORY.devices["mbp-riya"], jailbroken: true }).score, 10);
});
test("tokens: HS256 sign/verify, tamper, expiry, audience, device binding, key rotation", () => {
  const ring = new Keyring("s3cret"), tok = sign({ sub: "riya", aud: "prism-ztna", exp: 2000, cnf: { dev: deviceThumb("d1") } }, ring);
  assert.equal(verify(tok, ring, { now: 1000, device: "d1" }).ok, true);
  assert.equal(verify(tok, ring, { now: 2000 }).error, "expired");
  assert.equal(verify(tok, ring, { now: 1000, device: "d2" }).error, "token bound to another device");
  const [h, , s] = tok.split("."), forged = `${h}.${Buffer.from(JSON.stringify({ sub: "admin", aud: "prism-ztna", exp: 9e9 })).toString("base64url")}.${s}`;
  assert.equal(verify(forged, ring, { now: 1000 }).error, "bad signature");
  assert.equal(decode(tok).header.kid, "k1"); ring.rotate(); assert.equal(verify(tok, ring, { now: 1000 }).ok, true, "previous key still verifies"); ring.rotate();
  assert.equal(verify(tok, ring, { now: 1000 }).error, "unknown or retired key");
  const none = `${Buffer.from('{"alg":"none","kid":"k3"}').toString("base64url")}.${tok.split(".")[1]}.`; assert.equal(verify(none, ring, { now: 1000 }).error, "alg not allowed");
});
test("mesh: anycast ingress, backbone path, failover when a PoP dies", () => {
  const m = new Mesh({ connectors: CONNECTORS }), r = m.route(DIRECTORY.users.riya.home, "gitlab");
  assert.deepEqual(r.path, ["bom", "fra"]); assert.ok(r.rtt < r.direct, "private backbone beats the public internet");
  m.setPop("fra", false); const r2 = m.route(DIRECTORY.users.riya.home, "gitlab"); assert.ok(r2.ok); assert.ok(!r2.path.includes("fra"));
  m.setPop("iad", false); assert.match(m.route(DIRECTORY.users.riya.home, "gitlab").error, /no live PoP/);
});
test("broker: continuous verification revokes on posture drop; audit chain detects tampering", () => {
  const t = { v: 1e6 }, b = mk(t), l = b.login("riya", "mbp-riya");
  assert.equal(b.access(l.token, "prod-db", { deviceId: "mbp-riya", hour: 10 }).effect, "allow");
  t.v += 1200; assert.equal(b.access(l.token, "prod-db", { deviceId: "mbp-riya" }).effect, "challenge"); b.stepUp(l.sid); assert.equal(b.access(l.token, "prod-db", { deviceId: "mbp-riya" }).effect, "allow");
  b.dir.devices["mbp-riya"].edr = false; b.dir.devices["mbp-riya"].diskEncrypted = false; b.dir.devices["mbp-riya"].firewall = false; b.dir.devices["mbp-riya"].screenLockMin = 30;
  const d = b.access(l.token, "wiki", { deviceId: "mbp-riya" }); assert.equal(d.status, 401); assert.match(d.reason, /posture dropped to 40: session revoked/);
  assert.equal(b.access(l.token, "wiki", { deviceId: "mbp-riya" }).reason, "session revoked");
});
test("broker: login rules and audit integrity", () => {
  const b = mk(); assert.throws(() => b.login("riya", "tp-arjun"), /not registered/);
  b.dir.devices["byod-sam"].firewall = false; assert.equal(b.login("sam", "byod-sam").ok, false);
  const l = b.login("mei", deviceOf("mei")); b.access(l.token, "k8s-api", { deviceId: "mbp-mei", geo: { country: "KP" } });
  assert.equal(b.verifyAudit().ok, true); b.audit[1].effect = "tampered"; assert.equal(b.verifyAudit().ok, false);
});
test("HTTP proxy: login, allow + forward with identity headers, 403, step-up 401, bad token", async () => {
  const up = (await import("node:http")).createServer((q, r) => r.end(JSON.stringify({ path: q.url, user: q.headers["x-prism-user"], auth: !!q.headers.authorization })));
  await new Promise((r) => up.listen(0, r));
  const t = { v: Date.now() / 1000 }, b = mk(t), px = createProxy(b, { upstreams: { "prod-db": `http://127.0.0.1:${up.address().port}` } }); await new Promise((r) => px.listen(0, r));
  const base = `http://127.0.0.1:${px.address().port}`;
  try {
    const lr = await fetch(base + "/auth/login", { method: "POST", body: JSON.stringify({ user: "riya", device: "mbp-riya" }) }); assert.equal(lr.status, 200); const { token } = await lr.json();
    const H = { authorization: "Bearer " + token, "x-device-id": "mbp-riya" };
    const ok = await fetch(base + "/prod-db/tables?x=1", { headers: H }); assert.equal(ok.status, 200); assert.equal(ok.headers.get("x-prism-rule"), "sre-prod");
    assert.deepEqual(await ok.json(), { path: "/tables?x=1", user: "riya", auth: false });
    assert.equal((await fetch(base + "/payroll/", { headers: H })).status, 403);
    assert.equal((await fetch(base + "/prod-db/", { headers: { ...H, "x-device-id": "tp-arjun" } })).status, 401);
    assert.equal((await fetch(base + "/prod-db/", { headers: { authorization: "Bearer junk" } })).status, 401);
    t.v += 1200; const ch = await fetch(base + "/prod-db/", { headers: H }); assert.equal(ch.status, 401); assert.match(ch.headers.get("www-authenticate"), /insufficient_user_authentication/);
    assert.equal((await fetch(base + "/auth/mfa", { method: "POST", headers: H })).status, 200); assert.equal((await fetch(base + "/prod-db/", { headers: H })).status, 200);
    const au = await (await fetch(base + "/_audit")).json(); assert.equal(au.verify.ok, true);
  } finally { px.close(); up.close(); }
});
