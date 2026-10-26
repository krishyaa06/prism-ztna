// Overlay mesh: users anycast to nearby PoPs, PoPs peer over a backbone, app connectors dial OUT to two PoPs
// (no inbound ports on the private network). Routes are shortest RTT paths (Dijkstra) over healthy PoPs.
export const POPS = [
  { id: "bom", city: "Mumbai", lat: 19.08, lon: 72.88 }, { id: "sin", city: "Singapore", lat: 1.35, lon: 103.82 },
  { id: "fra", city: "Frankfurt", lat: 50.11, lon: 8.68 }, { id: "iad", city: "Ashburn", lat: 39.04, lon: -77.49 }, { id: "sfo", city: "San Jose", lat: 37.34, lon: -121.89 },
];
const R = 6371, rad = (d) => (d * Math.PI) / 180;
export function km(a, b) { const dl = rad(b.lat - a.lat), dn = rad(b.lon - a.lon), x = Math.sin(dl / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dn / 2) ** 2; return 2 * R * Math.asin(Math.sqrt(x)); }
// fibre ≈ 200 km/ms one way, real paths ~1.4× great-circle, plus per-hop processing
// public internet paths are ~1.5x great-circle, the private backbone ~1.15x
export const rttMs = (a, b, hop = 0.6, stretch = 1.5) => +((km(a, b) * stretch * 2) / 200 + hop).toFixed(2);

export class Mesh {
  constructor({ pops = POPS, connectors = {} } = {}) {
    this.pops = new Map(pops.map((p) => [p.id, { ...p, up: true, load: 0 }]));
    this.connectors = new Map(); for (const [app, c] of Object.entries(connectors)) this.addConnector(app, c);
  }
  addConnector(app, { lat, lon, region }) {
    const near = [...this.pops.values()].sort((a, b) => km(a, { lat, lon }) - km(b, { lat, lon })).slice(0, 2).map((p) => p.id);
    this.connectors.set(app, { app, lat, lon, region, pops: near });
  }
  setPop(id, up) { const p = this.pops.get(id); if (!p) throw new Error("unknown PoP " + id); p.up = up; }
  route(from, app) {
    const conn = this.connectors.get(app); if (!conn) return { ok: false, error: `no connector for ${app}` };
    const live = [...this.pops.values()].filter((p) => p.up); if (!live.length) return { ok: false, error: "all PoPs down" };
    // ingress: BGP anycast lands the user on the nearest live PoP
    const ing = live.reduce((a, b) => (km(from, a) <= km(from, b) ? a : b));
    const dist = new Map(live.map((p) => [p.id, Infinity])), prev = new Map(), todo = new Set(live.map((p) => p.id));
    dist.set(ing.id, rttMs(from, ing));
    while (todo.size) {
      let u = null; for (const id of todo) if (u == null || dist.get(id) < dist.get(u)) u = id; todo.delete(u);
      for (const id of todo) { const alt = dist.get(u) + rttMs(this.pops.get(u), this.pops.get(id), 0.3, 1.15); if (alt < dist.get(id)) { dist.set(id, alt); prev.set(id, u); } }
    }
    let best = null; for (const id of conn.pops) { const p = this.pops.get(id); if (!p.up) continue; const d = dist.get(id) + rttMs(p, conn, 0.4); if (!best || d < best.rtt) best = { egress: id, rtt: d }; }
    if (!best) return { ok: false, error: `connector for ${app} has no live PoP (${conn.pops.join(", ")} down)` };
    const path = [best.egress]; while (prev.has(path[0])) path.unshift(prev.get(path[0]));
    return { ok: true, path, ingress: path[0], egress: best.egress, rtt: +best.rtt.toFixed(1), direct: rttMs(from, conn) };
  }
}
