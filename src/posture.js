// Device posture: weighted checks -> 0..100 score and a trust tier. Jailbroken/rooted devices are capped.
export const CHECKS = [
  { id: "disk", label: "Disk encryption", weight: 20, test: (d) => !!d.diskEncrypted },
  { id: "edr", label: "EDR agent running", weight: 20, test: (d) => !!d.edr },
  { id: "patch", label: "OS patched (≤ 30 days)", weight: 15, test: (d) => patchFrac(d.patchAgeDays) },
  { id: "integrity", label: "Not jailbroken / rooted", weight: 15, test: (d) => !d.jailbroken },
  { id: "firewall", label: "Firewall on", weight: 10, test: (d) => !!d.firewall },
  { id: "lock", label: "Screen lock ≤ 5 min", weight: 10, test: (d) => d.screenLockMin != null && d.screenLockMin <= 5 },
  { id: "mdm", label: "Enrolled in MDM", weight: 10, test: (d) => !!d.managed },
];
function patchFrac(days) { if (days == null) return 0; if (days <= 30) return 1; if (days >= 90) return 0; return (90 - days) / 60; }
export function posture(device) {
  let score = 0; const checks = CHECKS.map((c) => { const r = c.test(device), frac = typeof r === "number" ? r : r ? 1 : 0; score += c.weight * frac; return { id: c.id, label: c.label, weight: c.weight, ok: frac >= 1, partial: frac > 0 && frac < 1, points: +(c.weight * frac).toFixed(1) }; });
  if (device.jailbroken) score = Math.min(score, 10);
  score = Math.round(score);
  return { score, tier: score >= 80 ? "trusted" : score >= 50 ? "limited" : "untrusted", checks, failed: checks.filter((c) => !c.ok).map((c) => c.id) };
}
