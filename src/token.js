// HS256 session tokens (JWT compact form) with key rotation and device binding.
import { hmacBytes, b64url, fromB64url, sha256, safeEqual } from "./lib/sha256.js";
const enc = (o) => b64url(new TextEncoder().encode(JSON.stringify(o)));
const dec = (s) => JSON.parse(new TextDecoder().decode(fromB64url(s)));

export class Keyring {
  constructor(secret = "dev-only-secret", kid = "k1") { this.keys = new Map([[kid, secret]]); this.current = kid; this.n = 1; }
  rotate(secret) { const kid = "k" + ++this.n; this.keys.set(kid, secret ?? `secret-${this.n}-${Math.random().toString(36).slice(2)}`); this.current = kid; for (const k of [...this.keys.keys()]) if (k !== kid && +k.slice(1) < this.n - 1) this.keys.delete(k); return kid; }
  get(kid) { return this.keys.get(kid); }
}
export const deviceThumb = (deviceId) => sha256("device:" + deviceId).slice(0, 22);

export function sign(claims, ring) {
  const head = enc({ alg: "HS256", typ: "JWT", kid: ring.current }), body = enc(claims);
  return `${head}.${body}.${b64url(hmacBytes(ring.get(ring.current), `${head}.${body}`))}`;
}
export function verify(token, ring, { now = Date.now() / 1000, aud = "prism-ztna", device } = {}) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return { ok: false, error: "malformed" };
  let h, c; try { h = dec(parts[0]); c = dec(parts[1]); } catch { return { ok: false, error: "malformed" }; }
  if (h.alg !== "HS256") return { ok: false, error: "alg not allowed" };
  const key = ring.get(h.kid); if (!key) return { ok: false, error: "unknown or retired key" };
  if (!safeEqual(b64url(hmacBytes(key, `${parts[0]}.${parts[1]}`)), parts[2])) return { ok: false, error: "bad signature" };
  if (c.aud !== aud) return { ok: false, error: "wrong audience" };
  if (c.nbf && now < c.nbf) return { ok: false, error: "not yet valid" };
  if (now >= c.exp) return { ok: false, error: "expired", claims: c };
  if (device !== undefined && c.cnf?.dev !== deviceThumb(device)) return { ok: false, error: "token bound to another device", claims: c };
  return { ok: true, claims: c, kid: h.kid };
}
export const decode = (token) => { const [h, c] = String(token).split("."); return { header: dec(h), claims: dec(c) }; };
