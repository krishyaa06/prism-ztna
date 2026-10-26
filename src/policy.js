// Prism ZTNA policy language: tokenizer, Pratt expression parser, compiler and evaluator.
//
//   app prod-db  host "10.0.4.12:5432"  tags [prod, data]
//   deny  "sanctioned-geo"  *              when geo.country in ["KP", "IR"]
//   allow "sre-prod"        prod-db, tag:k8s when "sre" in user.groups and device.score >= 80 require mfa within 15m
//
// Semantics: deny rules override allows, the first matching allow wins, anything else is denied by default.
const KW = new Set(["app", "allow", "deny", "when", "and", "or", "not", "in", "matches", "require", "mfa", "within", "host", "tags", "true", "false", "null"]);
const UNITS = { ms: 0.001, s: 1, m: 60, h: 3600, d: 86400 };

export class PolicyError extends Error {
  constructor(msg, line, col) { super(`${msg} at ${line}:${col}`); this.line = line; this.col = col; }
}

export function tokenize(src) {
  const out = []; let i = 0, line = 1, col = 1;
  const adv = (n = 1) => { for (let k = 0; k < n; k++) { if (src[i] === "\n") { line++; col = 1; } else col++; i++; } };
  while (i < src.length) {
    const ch = src[i];
    if (ch === "#") { while (i < src.length && src[i] !== "\n") adv(); continue; }
    if (ch === "\n") { out.push({ t: "nl", line, col }); adv(); continue; }
    if (/\s/.test(ch)) { adv(); continue; }
    const at = { line, col };
    if (ch === '"' || ch === "'") {
      let j = i + 1, s = ""; while (j < src.length && src[j] !== ch) { if (src[j] === "\\") j++; s += src[j++]; }
      if (j >= src.length) throw new PolicyError("unterminated string", line, col);
      out.push({ t: "str", v: s, ...at }); adv(j - i + 1); continue;
    }
    const num = /^(\d+(?:\.\d+)?)(ms|s|m|h|d)?(?![\w.])/.exec(src.slice(i));
    if (num) { out.push({ t: "num", v: +num[1] * (num[2] ? UNITS[num[2]] : 1), raw: num[0], ...at }); adv(num[0].length); continue; }
    const op = /^(==|!=|<=|>=|<|>|\(|\)|\[|\]|,|\*|!)/.exec(src.slice(i));
    if (op) { out.push({ t: "op", v: op[0], ...at }); adv(op[0].length); continue; }
    const id = /^[A-Za-z_][\w-]*(?::[\w-]+)?(?:\.[A-Za-z_][\w-]*)*/.exec(src.slice(i));
    if (id) { const v = id[0]; out.push({ t: KW.has(v) ? "kw" : "id", v, ...at }); adv(v.length); continue; }
    throw new PolicyError(`unexpected character '${ch}'`, line, col);
  }
  out.push({ t: "eof", line, col });
  return out;
}

// Binding powers for the Pratt parser.
const BP = { or: 10, and: 20, "==": 40, "!=": 40, "<": 40, "<=": 40, ">": 40, ">=": 40, in: 40, matches: 40 };

export function parse(src) {
  const toks = tokenize(src); let p = 0;
  const peek = () => toks[p], next = () => toks[p++];
  const is = (t, v) => peek().t === t && (v === undefined || peek().v === v);
  const expect = (t, v) => { const k = peek(); if (k.t !== t || (v !== undefined && k.v !== v)) throw new PolicyError(`expected ${v ?? t}, got ${k.v ?? k.t}`, k.line, k.col); return next(); };
  const skipNl = () => { while (is("nl")) next(); };

  function primary() {
    const k = next();
    if (k.t === "num") return { k: "lit", v: k.v, src: k.raw };
    if (k.t === "str") return { k: "lit", v: k.v, src: JSON.stringify(k.v) };
    if (k.t === "kw" && (k.v === "true" || k.v === "false")) return { k: "lit", v: k.v === "true", src: k.v };
    if (k.t === "kw" && k.v === "null") return { k: "lit", v: null, src: "null" };
    if (k.t === "kw" && k.v === "not" || k.t === "op" && k.v === "!") { const e = expr(30); return { k: "not", e, src: "not " + e.src }; }
    if (k.t === "op" && k.v === "(") { const e = expr(0); expect("op", ")"); return { ...e, src: `(${e.src})` }; }
    if (k.t === "op" && k.v === "[") {
      const items = []; while (!is("op", "]")) { items.push(primary()); if (!is("op", "]")) expect("op", ","); } next();
      return { k: "list", items, src: `[${items.map((x) => x.src).join(", ")}]` };
    }
    if (k.t === "id") return { k: "path", path: k.v.split("."), src: k.v };
    throw new PolicyError(k.t === "nl" || k.t === "eof" ? "unexpected end of line" : `unexpected ${k.v}`, k.line, k.col);
  }
  function expr(rbp) {
    let left = primary();
    for (;;) {
      const k = peek(), op = k.t === "kw" || k.t === "op" ? k.v : null;
      if (!op || !(op in BP) || BP[op] <= rbp) return left;
      next(); const right = expr(BP[op]);
      left = { k: op === "and" || op === "or" ? op : "cmp", op, l: left, r: right, src: `${left.src} ${op} ${right.src}`, line: k.line };
    }
  }
  const apps = {}, rules = [];
  skipNl();
  while (!is("eof")) {
    const k = next();
    if (k.t === "kw" && k.v === "app") {
      const name = expect("id").v, app = { name, host: null, tags: [] };
      while (!is("nl") && !is("eof")) {
        const a = next();
        if (a.v === "host") app.host = expect("str").v;
        else if (a.v === "tags") { expect("op", "["); while (!is("op", "]")) { const t = next(); app.tags.push(t.v); if (!is("op", "]")) expect("op", ","); } next(); }
        else throw new PolicyError(`unknown app attribute ${a.v}`, a.line, a.col);
      }
      apps[name] = app;
    } else if (k.t === "kw" && (k.v === "allow" || k.v === "deny")) {
      const name = is("str") ? next().v : `${k.v}-${rules.length + 1}`, targets = [];
      do { const t = next(); if (t.v === "*") targets.push("*"); else if (t.t === "id") targets.push(t.v); else throw new PolicyError(`bad target ${t.v ?? t.t}`, t.line, t.col); } while (is("op", ",") && next());
      let when = { k: "lit", v: true, src: "true" }, mfa = null;
      if (is("kw", "when")) { next(); when = expr(0); }
      if (is("kw", "require")) { next(); expect("kw", "mfa"); expect("kw", "within"); mfa = expect("num").v; }
      rules.push({ name, effect: k.v, targets, when, mfa, line: k.line });
    } else if (k.t !== "nl") throw new PolicyError(`expected app, allow or deny, got ${k.v ?? k.t}`, k.line, k.col);
    if (!is("eof")) expect("nl"); skipNl();
  }
  return { apps, rules };
}

const get = (ctx, path) => path.reduce((o, k) => (o == null ? undefined : o[k]), ctx);
const glob = (pat) => new RegExp("^" + String(pat).replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$");
function cmp(op, a, b) {
  switch (op) {
    case "==": return a === b; case "!=": return a !== b;
    case "<": return a < b; case "<=": return a <= b; case ">": return a > b; case ">=": return a >= b;
    case "in": return Array.isArray(b) ? b.includes(a) : typeof b === "string" ? b.includes(a) : false;
    case "matches": return typeof a === "string" && glob(b).test(a);
  }
}
// Evaluates an expression and records every comparison so a decision can explain itself.
export function evaluate(node, ctx, trace = []) {
  switch (node.k) {
    case "lit": return node.v;
    case "path": return get(ctx, node.path);
    case "list": return node.items.map((x) => evaluate(x, ctx, trace));
    case "not": { const v = !evaluate(node.e, ctx, node.e.k === "path" ? [] : trace); if (node.e.k === "path") trace.push({ src: node.src, ok: v, got: get(ctx, node.e.path) }); return v; }
    case "and": return leaf(node.l, ctx, trace) && leaf(node.r, ctx, trace);
    case "or": return leaf(node.l, ctx, trace) || leaf(node.r, ctx, trace);
    case "cmp": { const a = evaluate(node.l, ctx, []), b = evaluate(node.r, ctx, []), ok = !!cmp(node.op, a, b); trace.push({ src: node.src, ok, got: node.l.k === "path" ? a : node.r.k === "path" ? b : undefined }); return ok; }
  }
}
function leaf(node, ctx, trace) { const v = evaluate(node, ctx, trace); if (node.k === "path") trace.push({ src: node.src, ok: !!v, got: v }); return v; }
const truthyLeaf = leaf;

export class Policy {
  constructor(src) { this.src = src; const { apps, rules } = parse(src); this.apps = apps; this.rules = rules; this.version = hashStr(src); }
  targets(rule, app) {
    const a = this.apps[app] || { name: app, tags: [] };
    return rule.targets.some((t) => t === "*" || t === app || (t.startsWith("tag:") && a.tags.includes(t.slice(4))));
  }
  // ctx: { user, device, geo, time, mfa: { age } } — returns { effect, rule, reasons, trace }
  decide(ctx, app) {
    const c = { ...ctx, app: { name: app, tags: this.apps[app]?.tags || [] } }, trace = [];
    if (!this.apps[app]) return { effect: "deny", rule: null, reasons: [`unknown app ${app}`], trace };
    const relevant = this.rules.filter((r) => this.targets(r, app));
    for (const r of relevant.filter((r) => r.effect === "deny")) {
      const t = []; const hit = !!truthyLeaf(r.when, c, t); trace.push({ rule: r.name, effect: "deny", hit, leaves: t });
      if (hit) return { effect: "deny", rule: r.name, reasons: t.filter((x) => x.ok).map((x) => x.src), trace };
    }
    for (const r of relevant.filter((r) => r.effect === "allow")) {
      const t = []; const hit = !!truthyLeaf(r.when, c, t); trace.push({ rule: r.name, effect: "allow", hit, leaves: t });
      if (!hit) continue;
      const age = ctx.mfa?.age ?? Infinity;
      if (r.mfa != null && !(age <= r.mfa)) return { effect: "challenge", rule: r.name, reasons: [`mfa.age ${fmtDur(age)} > ${fmtDur(r.mfa)}: step-up required`], trace, mfa: r.mfa };
      return { effect: "allow", rule: r.name, reasons: t.filter((x) => x.ok).map((x) => x.src), trace };
    }
    const failed = trace.filter((x) => x.effect === "allow").flatMap((x) => x.leaves.filter((l) => !l.ok).map((l) => `${x.rule}: ${l.src}${l.got !== undefined ? ` (got ${JSON.stringify(l.got)})` : ""}`));
    return { effect: "deny", rule: "default-deny", reasons: failed.length ? failed : ["no rule grants access to " + app], trace };
  }
  // Static checks: unknown apps, rules that can never match, allows shadowed by a catch-all deny.
  lint() {
    const w = [];
    for (const r of this.rules) {
      for (const t of r.targets) if (t !== "*" && !t.startsWith("tag:") && !this.apps[t]) w.push({ line: r.line, rule: r.name, msg: `target ${t} is not a declared app` });
      for (const t of r.targets) if (t.startsWith("tag:") && !Object.values(this.apps).some((a) => a.tags.includes(t.slice(4)))) w.push({ line: r.line, rule: r.name, msg: `no app has ${t}` });
      if (r.when.k === "lit" && r.when.v === false) w.push({ line: r.line, rule: r.name, msg: "condition is always false" });
      if (r.effect === "deny" && r.when.k === "lit" && r.when.v === true && r.targets.includes("*")) w.push({ line: r.line, rule: r.name, msg: "unconditional deny * blocks every allow" });
      if (r.effect === "allow" && r.when.k === "lit" && r.when.v === true) w.push({ line: r.line, rule: r.name, msg: "unconditional allow: no identity or device check" });
    }
    for (const a of Object.keys(this.apps)) if (!this.rules.some((r) => r.effect === "allow" && this.targets(r, a))) w.push({ line: 0, rule: "-", msg: `app ${a} has no allow rule (always denied)` });
    return w;
  }
}
export const fmtDur = (s) => (s === Infinity ? "never" : s >= 3600 ? (s / 3600).toFixed(s % 3600 ? 1 : 0) + "h" : s >= 60 ? Math.round(s / 60) + "m" : Math.round(s) + "s");
export function hashStr(s) { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return (h >>> 0).toString(16).padStart(8, "0"); }
