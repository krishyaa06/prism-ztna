#!/usr/bin/env node
import { readFileSync } from "node:fs";
import http from "node:http";
import { Policy, Broker, Mesh, posture, decode, POLICY, DIRECTORY, CONNECTORS, deviceOf, fmtDur } from "../src/index.js";
import { c, table, header, fail, bar } from "../src/lib/cli.js";

const [cmd, ...rest] = process.argv.slice(2);
const flag = (n, d) => { const i = rest.indexOf("--" + n); return i >= 0 ? rest[i + 1] : d; };
const has = (n) => rest.includes("--" + n);
const pos = rest.filter((x, i) => !x.startsWith("--") && !(rest[i - 1] || "").startsWith("--"));
const HELP = `${c.bold("ztna")} — Prism ZTNA: zero-trust access proxy with a policy language, device posture and a routing mesh

  ztna lint [policy.ztna]                         parse a policy, list rules and static warnings
  ztna eval [policy.ztna] --user riya --app prod-db [--mfa 5m] [--country IN] [--hour 14] [--device id]
                                                  explain one access decision rule by rule
  ztna posture [--device mbp-riya]                device posture checks and score (all devices if omitted)
  ztna route --user riya --app gitlab [--down bom,fra]   shortest path through the PoP mesh
  ztna token --user riya                          issue and decode a session token
  ztna demo                                       logins, step-up MFA, compromised laptop, travel, PoP outage, audit
  ztna serve [--port 8080] [policy.ztna]          identity-aware HTTP proxy in front of demo apps
`;
const loadPolicy = () => (pos[0] && pos[0].endsWith(".ztna") ? readFileSync(pos[0], "utf8") : POLICY);
const dur = (s) => { const m = /^(\d+(?:\.\d+)?)(s|m|h)?$/.exec(s || ""); return m ? +m[1] * ({ s: 1, m: 60, h: 3600 }[m[2] || "s"]) : null; };
const eff = (e) => (e === "allow" ? c.green("ALLOW") : e === "challenge" ? c.yellow("STEP-UP") : c.red("DENY"));
const mkBroker = (src, t) => new Broker({ policy: src, directory: structuredClone(DIRECTORY), mesh: new Mesh({ connectors: CONNECTORS }), now: () => t.v });
try {
  if (!cmd || cmd === "-h" || cmd === "--help") console.log(HELP);
  else if (cmd === "lint") {
    const p = new Policy(loadPolicy()), w = p.lint();
    console.log(header("policy " + p.version, `${Object.keys(p.apps).length} apps · ${p.rules.length} rules`) + "\n");
    console.log(table(p.rules.map((r) => [String(r.line), r.effect === "deny" ? c.red("deny") : c.green("allow"), r.name, r.targets.join(", "), r.when.src.length > 64 ? r.when.src.slice(0, 61) + "…" : r.when.src, r.mfa ? c.yellow("mfa ≤ " + fmtDur(r.mfa)) : ""]), { head: ["line", "effect", "rule", "targets", "when", "step-up"] }));
    console.log("\n" + (w.length ? w.map((x) => `  ${c.yellow("warn")} ${x.line ? "line " + x.line + " " : ""}${x.rule !== "-" ? x.rule + ": " : ""}${x.msg}`).join("\n") : `  ${c.green("✓")} no warnings`));
  } else if (cmd === "eval") {
    const user = flag("user", "riya"), app = flag("app", "prod-db"), dev = flag("device", deviceOf(user)), t = { v: 1e6 }, b = mkBroker(loadPolicy(), t);
    const u = DIRECTORY.users[user] || fail("unknown user " + user), geo = flag("country") ? { ...u.home, country: flag("country") } : u.home;
    const l = b.login(user, dev); if (!l.ok) { console.log(header("eval", `${user}@${dev} → ${app}`) + "\n\n  " + eff("deny") + " at login: " + l.error); process.exit(0); }
    t.v += dur(flag("mfa", "5m")); const d = b.access(l.token, app, { deviceId: dev, geo, hour: +flag("hour", 14) });
    console.log(header("eval", `${user}@${dev} (posture ${l.posture.score}, ${geo.country}) → ${app}`) + "\n");
    for (const r of d.trace || []) { console.log(`  ${r.hit ? (r.effect === "deny" ? c.red("●") : c.green("●")) : c.dim("○")} ${r.effect.padEnd(5)} ${c.bold(r.rule)}`); for (const x of r.leaves) console.log(`      ${x.ok ? c.green("✓") : c.red("✗")} ${x.src}${x.got !== undefined ? c.dim("   ← " + JSON.stringify(x.got)) : ""}`); }
    console.log(`\n  ${eff(d.effect)} ${c.dim("rule")} ${d.rule || "-"}  ${c.dim(d.reason || "")}`);
    if (d.route) console.log(`  ${c.dim("route")} ${geo.city} → ${d.route.path.join(" → ")} → ${app} ${c.dim(`(${d.route.rtt} ms RTT, upstream ${d.upstream})`)}`);
  } else if (cmd === "posture") {
    const ids = flag("device") ? [flag("device")] : Object.keys(DIRECTORY.devices);
    if (ids.length > 1) { console.log(header("posture", `${ids.length} devices`) + "\n"); console.log(table(ids.map((id) => { const d = DIRECTORY.devices[id], p = posture(d); return [id, d.os, bar(p.score / 100, 20, p.score >= 80 ? c.green : p.score >= 50 ? c.yellow : c.red), String(p.score), p.tier, p.failed.join(" ")]; }), { head: ["device", "os", "", "score", "tier", "failed"] })); }
    else { const d = DIRECTORY.devices[ids[0]] || fail("unknown device " + ids[0]), p = posture(d); console.log(header(ids[0], `${d.os} · owner ${d.owner} · score ${p.score} (${p.tier})`) + "\n"); console.log(table(p.checks.map((x) => [x.ok ? c.green("✓") : x.partial ? c.yellow("~") : c.red("✗"), x.label, `${x.points}/${x.weight}`]), { head: ["", "check", "points"] })); }
  } else if (cmd === "route") {
    const m = new Mesh({ connectors: CONNECTORS }), u = DIRECTORY.users[flag("user", "riya")], app = flag("app", "gitlab");
    for (const id of (flag("down", "") || "").split(",").filter(Boolean)) m.setPop(id, false);
    const r = m.route(u.home, app); console.log(header("route", `${u.home.city} → ${app} (${CONNECTORS[app]?.region})`) + "\n");
    if (!r.ok) fail(r.error, 1);
    console.log(`  ${u.home.city} ─▶ ${r.path.map((p) => c.cyan(p)).join(" ═▶ ")} ─▶ connector:${app}\n\n  overlay RTT ${c.bold(r.rtt + " ms")}   public internet RTT ${r.direct} ms   ${c.dim("down: " + ([...m.pops.values()].filter((p) => !p.up).map((p) => p.id).join(", ") || "none"))}`);
  } else if (cmd === "token") {
    const user = flag("user", "riya"), t = { v: Math.floor(Date.now() / 1000) }, b = mkBroker(POLICY, t), l = b.login(user, deviceOf(user)); if (!l.ok) fail(l.error, 1);
    console.log(header("token", `${user} · ${deviceOf(user)} · HS256 · kid ${b.ring.current}`) + "\n\n" + c.dim(l.token) + "\n\n" + JSON.stringify(decode(l.token), null, 2));
  } else if (cmd === "demo") {
    const t = { v: 1e6 }, b = mkBroker(POLICY, t), row = (who, app, d) => console.log(`  ${who.padEnd(28)} ${app.padEnd(9)} ${eff(d.effect).padEnd(18)} ${c.dim((d.rule ? "[" + d.rule + "] " : "") + (d.reason || "").slice(0, 70))}${d.route ? c.dim(` via ${d.route.path.join(">")} ${d.route.rtt}ms`) : ""}`);
    console.log(header("demo", "Prism ZTNA · deny-overrides · continuous verification") + "\n");
    const s = {}; for (const u of Object.keys(DIRECTORY.users)) { const r = b.login(u, deviceOf(u)); s[u] = r; console.log(`  ${c.dim("login")} ${u.padEnd(6)} ${deviceOf(u).padEnd(10)} posture ${String(r.posture.score).padStart(3)} ${r.posture.tier.padEnd(9)} ${r.ok ? c.green("session " + r.sid) : c.red(r.error)}`); }
    console.log(""); const a = (u, app, o = {}) => row(`${u}${o.tag ? " " + o.tag : ""}`, app, b.access(s[u].token, app, { deviceId: o.dev || deviceOf(u), hour: o.hour ?? 14, geo: o.geo }));
    a("riya", "prod-db"); a("arjun", "gitlab"); a("arjun", "prod-db"); a("lena", "payroll"); a("sam", "wiki"); a("sam", "wiki", { hour: 23, tag: "(23:00)" }); a("sam", "gitlab");
    t.v += 1200; console.log(c.dim("\n  … 20 minutes later")); a("riya", "prod-db"); b.stepUp(s.riya.sid); a("riya", "prod-db", { tag: "(after MFA)" });
    console.log(c.dim("\n  riya's laptop: EDR killed, device jailbroken")); b.dir.devices["mbp-riya"].edr = false; b.dir.devices["mbp-riya"].jailbroken = true; a("riya", "grafana"); a("riya", "wiki", { tag: "(retry)" });
    console.log(c.dim("\n  mei connects from a sanctioned country")); a("mei", "k8s-api", { geo: { country: "KP", city: "Pyongyang", lat: 39.03, lon: 125.75 } });
    console.log(c.dim("\n  stolen token replayed from another device")); a("noah", "wiki", { dev: "tp-arjun", tag: "(wrong device)" });
    console.log(c.dim("\n  PoP sin goes down")); b.stepUp(s.mei.sid); a("mei", "k8s-api", { tag: "(before)" }); b.mesh.setPop("sin", false); a("mei", "k8s-api", { tag: "(sin down)" });
    const v = b.verifyAudit(); console.log(`\n  audit ${v.ok ? c.green("✓ chain intact") : c.red("✗ " + v.error)} · ${v.entries} entries · head ${v.head.slice(0, 16)}…  ${c.dim(JSON.stringify(b.stats))}`);
    const bad = b.audit.find((e) => e.effect === "deny"); bad.effect = "allow"; const v2 = b.verifyAudit(); console.log(`  flip deny → allow in entry #${bad.seq} → ${v2.ok ? c.red("undetected") : c.green("✓ detected: " + v2.error + " at seq " + v2.at)}`);
  } else if (cmd === "serve") {
    const port = +flag("port", 8080), b = new Broker({ policy: loadPolicy(), directory: structuredClone(DIRECTORY), mesh: new Mesh({ connectors: CONNECTORS }) }), ups = {};
    const { createProxy } = await import("../src/node/proxy.js");
    for (const [i, app] of Object.keys(b.policy.apps).entries()) { const p = port + 100 + i; ups[app] = `http://127.0.0.1:${p}`; http.createServer((q, r) => { r.writeHead(200, { "content-type": "application/json" }); r.end(JSON.stringify({ app, path: q.url, user: q.headers["x-prism-user"], posture: q.headers["x-prism-score"], sawAuthHeader: !!q.headers.authorization })); }).listen(p, "127.0.0.1"); }
    createProxy(b, { upstreams: ups, adminKey: process.env.ZTNA_ADMIN_KEY || null, log: (l) => console.log(c.dim(new Date().toISOString().slice(11, 19)) + " " + l) }).listen(port, () => {
      console.log(header("ztna", `policy ${b.policy.version} · ${Object.keys(ups).length} private apps on 127.0.0.1 · http://localhost:${port}`) + "\n");
      console.log(c.dim(`  TOKEN=$(curl -s localhost:${port}/auth/login -d '{"user":"riya","device":"mbp-riya"}' | node -pe 'JSON.parse(require("fs").readFileSync(0)).token')\n  curl -H "authorization: Bearer $TOKEN" -H "x-device-id: mbp-riya" localhost:${port}/prod-db/tables\n  curl -H "authorization: Bearer $TOKEN" -H "x-device-id: mbp-riya" localhost:${port}/payroll/   # 403\n  curl localhost:${port}/_audit\n`));
    });
  } else fail(`unknown command ${cmd}\n\n${HELP}`);
} catch (e) { fail(e.message); }
