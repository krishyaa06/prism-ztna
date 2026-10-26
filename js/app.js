import { Broker, Mesh, Policy, posture, POLICY, DIRECTORY, CONNECTORS, deviceOf, fmtDur } from "../src/index.js";
import { $, esc, fmt, toast, Loop, bindLoop, LogView, Kpis, Chart, fit, hexA } from "./pro.js";

const OK = "#34f5c5", BAD = "#ff5c8a", WARN = "#ffb547", ACC2 = "#7c5cff", MUTED = "#5f6884";
const mono = "JetBrains Mono, monospace";
const dir = structuredClone(DIRECTORY), pristine = structuredClone(DIRECTORY.devices);
let simT = Date.UTC(2026, 9, 26, 7, 20) / 1000; // sim clock: 40 sim seconds per real second
const B = new Broker({ policy: POLICY, directory: dir, mesh: new Mesh({ connectors: CONNECTORS }), now: () => simT });
const USERS = Object.keys(dir.users), APPS = Object.keys(CONNECTORS), POPS = [...B.mesh.pops.keys()];
const PREFS = { riya: ["prod-db", "grafana", "k8s-api", "gitlab", "wiki"], arjun: ["gitlab", "grafana", "wiki", "prod-db"], mei: ["k8s-api", "grafana", "gitlab", "prod-db"], lena: ["payroll", "wiki", "gitlab"], sam: ["wiki", "wiki", "gitlab"], noah: ["gitlab", "grafana", "wiki", "k8s-api"] };
const st = Object.fromEntries(USERS.map((u) => [u, { token: null, sid: null, retry: 0, mfaPending: 0, geo: null, last: null, flash: 0 }]));
let rr = 7; const rand = () => (rr = (rr * 48271) % 2147483647) / 2147483647;
const pick = (a) => a[Math.floor(rand() * a.length)];
let selected = null, packets = [], bursts = [], popFlash = {}, appFlash = {}, rtts = [], win = { allow: 0, deny: 0, challenge: 0 }, total = 0;
const log = new LogView($("#log"), 200), _html = log.html.bind(log);
const clockStr = () => new Date(simT * 1000).toISOString().slice(11, 19);
log.html = (x) => _html(x, clockStr());

// ---------- sessions + traffic ----------
function login(u) {
  const s = st[u], dev = deviceOf(u);
  try {
    const r = B.login(u, dev, { mfa: true });
    if (r.ok) { Object.assign(s, { token: r.token, sid: r.sid }); log.html(`<span class="acc">LOGIN</span> ${u} <span class="dim">${dev} · posture ${r.posture.score} · ${r.sid}</span>`); }
    else { s.retry = 4; log.html(`<span class="bad">LOGIN DENIED</span> ${u} <span class="dim">${esc(r.error)}</span>`); }
  } catch (e) { s.retry = 4; }
}
const hour = () => new Date(simT * 1000).getUTCHours();
function request(u, app) {
  const s = st[u]; if (!s.token) return;
  const d = B.access(s.token, app, { deviceId: deviceOf(u), geo: s.geo || undefined, hour: hour() });
  total++; win[d.effect]++; s.last = { app, d, at: simT };
  if (d.route) rtts.push(d.route.rtt);
  const g = s.geo || dir.users[u].home, ing = d.route ? d.route.ingress : nearestPop(g);
  packets.push({ u, app, eff: d.effect, path: d.route ? d.route.path : [ing], k: 0, seg: 0, done: false });
  if (d.effect === "allow") { if (rand() < 0.22) log.html(`<span class="ok">ALLOW</span> ${u} → ${app} <span class="dim">[${d.rule}] ${d.route.path.join("›")} ${d.route.rtt}ms</span>`); }
  else if (d.effect === "challenge") { log.html(`<span class="warn">STEP-UP</span> ${u} → ${app} <span class="dim">${esc(d.reason)}</span>`); if (!s.mfaPending) s.mfaPending = 1.4; }
  else {
    log.html(`<span class="bad">DENY</span> ${u} → ${app} <span class="dim">${d.rule ? "[" + d.rule + "] " : ""}${esc(d.reason.slice(0, 90))}</span>`);
    if (d.status === 401) { s.token = null; s.sid = null; s.retry = 1.5; }
  }
  if (selected === u || !selected) showDecision(u, app, d);
}
function nearestPop(g) { let best = null, bd = Infinity; for (const p of B.mesh.pops.values()) { if (!p.up) continue; const dd = (p.lat - g.lat) ** 2 + (p.lon - g.lon) ** 2; if (dd < bd) { bd = dd; best = p.id; } } return best || POPS[0]; }
B.on((e) => { if (e.type === "revoke") log.html(`<span class="bad">REVOKED</span> ${e.user} <span class="dim">${esc(e.reason)}</span>`); });

// ---------- KPIs + charts ----------
const kp = new Kpis($("#kpis"), [
  { key: "req", label: "Requests", tone: "acc" }, { key: "ok", label: "Allowed", fmt: (v) => (v * 100).toFixed(1) + "%" }, { key: "deny", label: "Denied" },
  { key: "mfa", label: "Step-ups" }, { key: "sess", label: "Sessions" }, { key: "rtt", label: "RTT p50", fmt: (v) => v.toFixed(0) + " ms" },
]);
const ch1 = new Chart($("#ch1"), { series: [{ label: "allow", color: OK }, { label: "deny", color: BAD }, { label: "step-up", color: WARN }], min: 0, points: 60, area: false, fmtY: (v) => v.toFixed(0) });
const ch2 = new Chart($("#ch2"), { series: [{ label: "p50", color: "--accent" }, { label: "p95", color: ACC2 }], min: 0, points: 60, area: false, fmtY: (v) => v.toFixed(0) });
const q = (a, p) => { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };

// ---------- canvas ----------
let L = null;
function layout(w, H) {
  const narrow = w < 600, top = narrow ? 44 : 40, bot = 30, uw = narrow ? 70 : 150, aw = narrow ? 92 : 168;
  const ys = (n) => Array.from({ length: n }, (_, i) => top + ((H - top - bot) * (i + 0.5)) / n);
  const uy = ys(USERS.length), py = ys(POPS.length), ay = ys(APPS.length), px = narrow ? w * 0.47 : w * 0.46;
  L = { narrow, users: Object.fromEntries(USERS.map((u, i) => [u, { x: narrow ? 22 : 34, y: uy[i] }])), pops: Object.fromEntries(POPS.map((p, i) => [p, { x: px, y: py[i] }])), apps: Object.fromEntries(APPS.map((a, i) => [a, { x: w - aw - 10, y: ay[i], w: aw, h: Math.min(narrow ? 46 : 44, (H - top - bot) / APPS.length - 10) }])), uw, w, H };
  return L;
}
const appIn = (a) => { const b = L.apps[a]; return { x: b.x, y: b.y }; };
const arcCtrl = (a, b) => { const A = L.pops[a], Bp = L.pops[b], d = Math.abs(POPS.indexOf(a) - POPS.indexOf(b)); return { x: A.x + (L.narrow ? 16 : 26) * d, y: (A.y + Bp.y) / 2 }; };
function pathPts(pk) {
  const u = L.users[pk.u], segs = [], first = L.pops[pk.path[0]];
  segs.push({ a: { x: u.x + 16, y: u.y }, b: first });
  if (pk.eff !== "allow") return segs;
  for (let i = 1; i < pk.path.length; i++) segs.push({ a: L.pops[pk.path[i - 1]], b: L.pops[pk.path[i]], c: arcCtrl(pk.path[i - 1], pk.path[i]) });
  segs.push({ a: L.pops[pk.path.at(-1)], b: appIn(pk.app) });
  return segs;
}
const bez = (s, t) => (s.c ? { x: (1 - t) ** 2 * s.a.x + 2 * (1 - t) * t * s.c.x + t * t * s.b.x, y: (1 - t) ** 2 * s.a.y + 2 * (1 - t) * t * s.c.y + t * t * s.b.y } : { x: s.a.x + (s.b.x - s.a.x) * t, y: s.a.y + (s.b.y - s.a.y) * t });
const segLen = (s) => (s.c ? Math.hypot(s.c.x - s.a.x, s.c.y - s.a.y) + Math.hypot(s.b.x - s.c.x, s.b.y - s.c.y) : Math.hypot(s.b.x - s.a.x, s.b.y - s.a.y));
let dashT = 0;
function draw(dt = 0) {
  const { ctx, w, h: H } = fit($("#net")); layout(w, H); ctx.clearRect(0, 0, w, H); dashT += dt * 30;
  const fs = L.narrow ? 10 : 11;
  // connector tunnels (outbound from app to its two nearest PoPs)
  ctx.setLineDash([3, 5]); ctx.lineDashOffset = -dashT; ctx.lineWidth = 1;
  for (const a of APPS) { const c = B.mesh.connectors.get(a), b = L.apps[a]; for (const p of c.pops) { const P = L.pops[p], up = B.mesh.pops.get(p).up; ctx.strokeStyle = up ? hexA(ACC2, 0.35) : "#ffffff0d"; ctx.beginPath(); ctx.moveTo(b.x, b.y); ctx.lineTo(P.x + 16, P.y); ctx.stroke(); } }
  ctx.setLineDash([]);
  // backbone mesh
  for (let i = 0; i < POPS.length; i++) for (let j = i + 1; j < POPS.length; j++) { const a = L.pops[POPS[i]], b = L.pops[POPS[j]], c = arcCtrl(POPS[i], POPS[j]), up = B.mesh.pops.get(POPS[i]).up && B.mesh.pops.get(POPS[j]).up; ctx.strokeStyle = up ? "#ffffff12" : "#ffffff06"; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.quadraticCurveTo(c.x, c.y, b.x, b.y); ctx.stroke(); }
  // users
  const now = performance.now();
  for (const u of USERS) {
    const p = L.users[u], s = st[u], dev = dir.devices[deviceOf(u)], ps = posture(dev), col = ps.score >= 80 ? OK : ps.score >= 50 ? WARN : BAD, sel = selected === u;
    ctx.fillStyle = sel ? hexA(OK, 0.12) : "#0c1222"; ctx.strokeStyle = sel ? OK : "#232c45"; ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(p.x, p.y, 15, 0, 7); ctx.fill(); ctx.stroke();
    ctx.strokeStyle = "#ffffff10"; ctx.lineWidth = 3; ctx.beginPath(); ctx.arc(p.x, p.y, 19, 0, 7); ctx.stroke();
    ctx.strokeStyle = col; ctx.beginPath(); ctx.arc(p.x, p.y, 19, -Math.PI / 2, -Math.PI / 2 + (Math.PI * 2 * ps.score) / 100); ctx.stroke();
    ctx.fillStyle = "#e8ecf8"; ctx.font = `600 11px ${mono}`; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText(u.slice(0, 2).toUpperCase(), p.x, p.y + 1);
    ctx.textBaseline = "alphabetic"; ctx.textAlign = "left";
    const tx = L.narrow ? p.x - 18 : p.x + 28, ty = L.narrow ? p.y + 34 : p.y - 2;
    ctx.fillStyle = "#cfd6ea"; ctx.font = `600 ${fs}px ${mono}`; ctx.fillText(u, tx, ty);
    ctx.fillStyle = s.token ? MUTED : BAD; ctx.font = `${fs - 1}px ${mono}`;
    if (!L.narrow) ctx.fillText(`${s.geo ? s.geo.country + " ⚠" : dir.users[u].home.city.slice(0, 9)} · ${ps.score}`, tx, ty + 13);
    if (s.geo) { ctx.fillStyle = BAD; ctx.font = `600 9px ${mono}`; ctx.fillText(s.geo.country, p.x + 11, p.y - 14); }
    ctx.fillStyle = s.token ? OK : BAD; ctx.beginPath(); ctx.arc(p.x + 13, p.y + 13, 3.2, 0, 7); ctx.fill();
  }
  // PoPs
  for (const id of POPS) {
    const P = L.pops[id], pop = B.mesh.pops.get(id), f = popFlash[id] ? Math.max(0, 1 - (now - popFlash[id].t) / 500) : 0;
    if (f > 0) { ctx.fillStyle = hexA(popFlash[id].c, 0.25 * f); ctx.beginPath(); ctx.arc(P.x, P.y, 18 + 14 * (1 - f), 0, 7); ctx.fill(); }
    ctx.fillStyle = pop.up ? "#0e1730" : "#160b12"; ctx.strokeStyle = pop.up ? hexA(OK, 0.7) : BAD; ctx.lineWidth = 1.5; ctx.beginPath();
    for (let k = 0; k < 6; k++) { const a = Math.PI / 6 + (k * Math.PI) / 3; ctx[k ? "lineTo" : "moveTo"](P.x + 17 * Math.cos(a), P.y + 17 * Math.sin(a)); } ctx.closePath(); ctx.fill(); ctx.stroke();
    ctx.fillStyle = pop.up ? "#e8ecf8" : BAD; ctx.font = `600 10px ${mono}`; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText(id, P.x, P.y + 1); ctx.textBaseline = "alphabetic";
    if (!pop.up) { ctx.strokeStyle = BAD; ctx.beginPath(); ctx.moveTo(P.x - 10, P.y - 10); ctx.lineTo(P.x + 10, P.y + 10); ctx.stroke(); }
    if (!L.narrow) { ctx.fillStyle = MUTED; ctx.font = `10px ${mono}`; ctx.textAlign = "right"; ctx.fillText(pop.up ? pop.city : "DOWN", P.x - 24, P.y + 4); }
  }
  // apps
  for (const a of APPS) {
    const b = L.apps[a], c = CONNECTORS[a], f = appFlash[a] ? Math.max(0, 1 - (now - appFlash[a]) / 600) : 0, y = b.y - b.h / 2;
    ctx.fillStyle = f > 0 ? hexA(OK, 0.06 + 0.14 * f) : "#0c1222"; ctx.strokeStyle = f > 0 ? hexA(OK, 0.4 + 0.5 * f) : "#232c45"; ctx.lineWidth = 1; ctx.beginPath(); ctx.roundRect(b.x, y, b.w, b.h, 10); ctx.fill(); ctx.stroke();
    ctx.textAlign = "left"; ctx.fillStyle = "#e8ecf8"; ctx.font = `600 ${fs}px ${mono}`; ctx.fillText("🔒 " + a, b.x + 9, y + (L.narrow ? 18 : 18));
    ctx.fillStyle = MUTED; ctx.font = `${fs - 1}px ${mono}`; ctx.fillText(L.narrow ? c.region.replace(/-\d$/, "") : `${c.region} · ${B.policy.apps[a]?.tags.join(",") || "—"}`, b.x + 9, y + (L.narrow ? 34 : 33));
  }
  // packets
  for (let i = packets.length - 1; i >= 0; i--) {
    const pk = packets[i], segs = pathPts(pk), s = segs[pk.seg]; if (!s) { packets.splice(i, 1); continue; }
    pk.k += (dt * 340) / Math.max(20, segLen(s));
    if (pk.k >= 1) {
      pk.k = 0; pk.seg++;
      if (pk.seg === 1) popFlash[pk.path[0]] = { t: now, c: pk.eff === "allow" ? OK : pk.eff === "challenge" ? WARN : BAD };
      if (pk.seg >= segs.length) { if (pk.eff === "allow") appFlash[pk.app] = now; else bursts.push({ x: L.pops[pk.path[0]].x, y: L.pops[pk.path[0]].y, t: now, eff: pk.eff }); packets.splice(i, 1); continue; }
    }
    const P = bez(segs[pk.seg], pk.k), col = pk.eff === "allow" ? OK : pk.eff === "challenge" ? WARN : BAD;
    ctx.fillStyle = col; ctx.shadowColor = col; ctx.shadowBlur = 8; ctx.beginPath(); ctx.arc(P.x, P.y, 2.6, 0, 7); ctx.fill(); ctx.shadowBlur = 0;
  }
  for (let i = bursts.length - 1; i >= 0; i--) {
    const b = bursts[i], k = (now - b.t) / 700; if (k >= 1) { bursts.splice(i, 1); continue; }
    const col = b.eff === "challenge" ? WARN : BAD; ctx.globalAlpha = 1 - k; ctx.strokeStyle = col; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(b.x - 22, b.y - 16, 6 + k * 10, 0, 7); ctx.stroke();
    ctx.fillStyle = col; ctx.font = `600 9px ${mono}`; ctx.textAlign = "center"; ctx.fillText(b.eff === "challenge" ? "MFA" : "✕", b.x - 22, b.y - 13); ctx.globalAlpha = 1;
  }
  // legend
  ctx.font = `10px ${mono}`; ctx.textAlign = "left"; let lx = 12;
  for (const [n, c] of [["allow", OK], ["deny", BAD], ["step-up", WARN], ["tunnel", ACC2]]) { ctx.fillStyle = c; ctx.fillRect(lx, H - 15, 8, 8); ctx.fillStyle = "#8d94ad"; ctx.fillText(n, lx + 12, H - 8); lx += ctx.measureText(n).width + 24; }
}
$("#net").addEventListener("click", (e) => {
  const r = e.target.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top; if (!L) return;
  for (const id of POPS) { const P = L.pops[id]; if (Math.hypot(P.x - x, P.y - y) < 22) return togglePop(id); }
  for (const u of USERS) { const P = L.users[u]; if (Math.hypot(P.x - x, P.y - y) < 24) { selected = selected === u ? null : u; $("#who").textContent = selected || "latest"; $("#qu").value = u; if (st[u].last) showDecision(u, st[u].last.app, st[u].last.d); return; } }
});

// ---------- inspector ----------
function showDecision(u, app, d, whatIf = false) {
  const cls = d.effect === "allow" ? "ok" : d.effect === "challenge" ? "warn" : "bad";
  let html = `<div><span class="${cls}">${d.effect.toUpperCase()}</span> ${u} → ${app} ${d.rule ? `<span class="dim">rule</span> ${esc(d.rule)}` : ""}${whatIf ? ' <span class="dim">(what-if)</span>' : ""}</div>`;
  if (d.reason || d.reasons) html += `<div class="dim">${esc(d.reason || d.reasons.join("; "))}</div>`;
  for (const r of d.trace || []) {
    html += `<div class="rule ${r.hit ? "hit" : "miss"}">${r.hit ? "●" : "○"} ${r.effect} ${esc(r.rule)}</div>`;
    for (const l of r.leaves) html += `<div class="leaf"><span class="${l.ok ? "ok" : "bad"}">${l.ok ? "✓" : "✗"}</span> ${esc(l.src)}${l.got !== undefined ? ` <span class="dim">← ${esc(JSON.stringify(l.got))}</span>` : ""}</div>`;
  }
  if (d.route) html += `<div style="margin-top:6px"><span class="acc">route</span> ${d.route.path.join(" → ")} → ${app} <span class="dim">${d.route.rtt} ms (internet ${d.route.direct} ms)</span></div>`;
  $("#insp").innerHTML = html;
}
$("#qu").innerHTML = USERS.map((u) => `<option>${u}</option>`).join(""); $("#qa").innerHTML = APPS.map((a) => `<option>${a}</option>`).join("");
$("#ask").onclick = () => { const u = $("#qu").value, a = $("#qa").value; selected = u; $("#who").textContent = u; try { showDecision(u, a, B.explain(u, a, { geo: st[u].geo || undefined, hour: hour() }), true); } catch (e) { $("#insp").innerHTML = `<div class="bad">${esc(e.message)}</div>`; } };

// ---------- policy editor ----------
const pol = $("#pol"); pol.value = POLICY;
function lintNow() {
  try { const p = new Policy(pol.value), w = p.lint(); pol.classList.remove("err"); $("#pstat").className = "pstat " + (w.length ? "warn" : "ok"); $("#pstat").textContent = w.length ? `⚠ ${w[0].msg}${w.length > 1 ? ` (+${w.length - 1})` : ""}` : `✓ ${p.rules.length} rules · ${Object.keys(p.apps).length} apps`; return p; }
  catch (e) { pol.classList.add("err"); $("#pstat").className = "pstat bad"; $("#pstat").textContent = "✗ " + e.message; return null; }
}
pol.addEventListener("input", lintNow);
$("#apply").onclick = () => { if (!lintNow()) return toast("Fix the policy error first"); const p = B.setPolicy(pol.value); $("#pver").textContent = "v " + p.version; log.html(`<span class="acc">POLICY</span> applied ${p.version} <span class="dim">${p.rules.length} rules · takes effect on the next request</span>`); toast("Policy applied. Every new request is evaluated against it."); };
$("#revert").onclick = () => { pol.value = POLICY; lintNow(); $("#apply").click(); };
$("#pver").textContent = "v " + B.policy.version; lintNow();

// ---------- controls ----------
function togglePop(id) { const p = B.mesh.pops.get(id); B.mesh.setPop(id, !p.up); log.html(`<span class="${p.up ? "ok" : "bad"}">PoP ${p.up ? "UP" : "DOWN"}</span> ${id} <span class="dim">${p.city}${p.up ? "" : " · traffic re-anycasts to the next PoP"}</span>`); if (id === "bom") $("#pop").textContent = p.up ? "Fail PoP bom" : "Restore PoP bom"; toast(p.up ? `${id} is back` : `${id} down: users re-route, connectors fail over`); }
$("#pop").onclick = () => togglePop("bom");
$("#pwn").onclick = () => {
  const d = dir.devices["mbp-riya"], bad = !d.jailbroken;
  if (bad) Object.assign(d, { edr: false, jailbroken: true, firewall: false }); else Object.assign(d, pristine["mbp-riya"]);
  $("#pwn").textContent = bad ? "Remediate riya's laptop" : "Compromise riya's laptop"; $("#pwn").classList.toggle("on", bad);
  log.html(bad ? `<span class="bad">POSTURE</span> mbp-riya <span class="dim">EDR stopped · jailbreak detected · score ${posture(d).score}</span>` : `<span class="ok">POSTURE</span> mbp-riya <span class="dim">remediated · score ${posture(d).score}</span>`);
  toast(bad ? "riya's laptop is compromised: the next request revokes her session" : "Laptop remediated: riya can log in again");
  selected = "riya"; $("#who").textContent = "riya";
};
$("#travel").onclick = () => { const s = st.mei; s.geo = s.geo ? null : { country: "KP", city: "Pyongyang", lat: 39.03, lon: 125.75 }; $("#travel").textContent = s.geo ? "mei back home (SG)" : "mei logs in from KP"; $("#travel").classList.toggle("on", !!s.geo); toast(s.geo ? "mei's traffic now geolocates to KP: deny rule sanctioned-geo" : "mei is back in Singapore"); selected = "mei"; $("#who").textContent = "mei"; };
$("#rotate").onclick = () => { const kid = B.ring.rotate(); const kept = [...B.ring.keys.keys()]; log.html(`<span class="acc">KEY ROTATION</span> signing with ${kid} <span class="dim">verifying: ${kept.join(", ")}</span>`); toast(`New tokens signed with ${kid}. Tokens on older retired keys must re-authenticate.`); };

// ---------- loop ----------
let acc = 0, spawn = 0;
function tick(dt, chart = true) {
  simT += dt * 40;
  for (const u of USERS) {
    const s = st[u];
    if (!s.token) { s.retry -= dt; if (s.retry <= 0) login(u); }
    if (s.mfaPending) { s.mfaPending -= dt; if (s.mfaPending <= 0) { s.mfaPending = 0; if (s.sid && rand() < 0.85) { B.stepUp(s.sid); log.html(`<span class="ok">MFA ✓</span> ${u} <span class="dim">WebAuthn step-up · session ${s.sid}</span>`); } } }
  }
  spawn += dt * 9; for (; spawn >= 1; spawn--) { const u = pick(USERS); request(u, pick(PREFS[u])); }
  acc += dt;
  if (acc >= 1) {
    const r = rtts.splice(0, Math.max(0, rtts.length - 60)) && rtts.slice(), a = B.stats;
    if (chart) { ch1.push(win.allow / acc, win.deny / acc, win.challenge / acc); if (r.length) ch2.push(q(r, 0.5), q(r, 0.95)); }
    win = { allow: 0, deny: 0, challenge: 0 }; acc = 0;
    const done = a.allow + a.deny + a.challenge;
    kp.set({ req: total, ok: done ? a.allow / done : 1, deny: a.deny, mfa: a.challenge, sess: B.sessions.size, rtt: r.length ? q(r, 0.5) : kp.cur.rtt || 0 });
    kp.tone("ok", a.allow / (done || 1) > 0.6 ? "ok" : "warn");
    const d = new Date(simT * 1000); $("#clock").textContent = `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")} UTC · sim ×40`;
  }
}
for (let i = 0; i < 600; i++) tick(0.1); // prewarm 60 s so charts have history
packets = []; bursts = [];
const loop = new Loop((dt) => { tick(dt); draw(dt); });
bindLoop(loop, $("#sim"));
draw(); loop.start();
setTimeout(() => $("#pwn").click(), 2200);
setTimeout(() => $("#travel").click(), 4200);
setTimeout(() => { $("#pwn").click(); $("#travel").click(); selected = null; $("#who").textContent = "latest"; }, 16000);
addEventListener("resize", () => draw());
