// Demo directory, apps and policy shared by the CLI, the tests and the live simulator.
export const POLICY = `# Prism ZTNA policy · deny overrides allow · default deny
app grafana    host "grafana.internal:3000"   tags [observability]
app gitlab     host "gitlab.internal:443"     tags [eng]
app prod-db    host "10.0.4.12:5432"          tags [prod, data]
app k8s-api    host "k8s.prod.internal:6443"  tags [prod]
app payroll    host "payroll.internal:8443"   tags [finance]
app wiki       host "wiki.internal:80"        tags [docs]

deny  "sanctioned-geo"  *          when geo.country in ["KP", "IR", "SY", "CU"]
deny  "untrusted-device" tag:prod  when device.tier != "trusted" or device.jailbroken
allow "everyone-docs"   wiki       when user.type == "employee" or (user.type == "contractor" and time.hour >= 8 and time.hour < 20)
allow "eng-tools"       gitlab, grafana  when "eng" in user.groups and device.managed
allow "sre-prod"        tag:prod   when "sre" in user.groups and device.score >= 80 require mfa within 15m
allow "finance-payroll" payroll    when user.dept == "finance" and device.os in ["macos", "windows"] and device.score >= 70 require mfa within 1h
`;
export const DIRECTORY = {
  users: {
    riya: { id: "riya", email: "riya@prism.dev", groups: ["eng", "sre"], type: "employee", dept: "platform", home: { country: "IN", city: "Mumbai", lat: 19.08, lon: 72.88 } },
    arjun: { id: "arjun", email: "arjun@prism.dev", groups: ["eng"], type: "employee", dept: "product", home: { country: "IN", city: "Bengaluru", lat: 12.97, lon: 77.59 } },
    mei: { id: "mei", email: "mei@prism.dev", groups: ["eng", "sre"], type: "employee", dept: "platform", home: { country: "SG", city: "Singapore", lat: 1.35, lon: 103.82 } },
    lena: { id: "lena", email: "lena@prism.dev", groups: ["finance"], type: "employee", dept: "finance", home: { country: "DE", city: "Berlin", lat: 52.52, lon: 13.4 } },
    sam: { id: "sam", email: "sam@contractor.io", groups: ["vendor"], type: "contractor", dept: "design", home: { country: "US", city: "Austin", lat: 30.27, lon: -97.74 } },
    noah: { id: "noah", email: "noah@prism.dev", groups: ["eng"], type: "employee", dept: "ml", home: { country: "US", city: "Seattle", lat: 47.61, lon: -122.33 } },
  },
  devices: {
    "mbp-riya": { id: "mbp-riya", owner: "riya", os: "macos", managed: true, diskEncrypted: true, edr: true, firewall: true, screenLockMin: 2, patchAgeDays: 6, jailbroken: false },
    "tp-arjun": { id: "tp-arjun", owner: "arjun", os: "linux", managed: true, diskEncrypted: true, edr: true, firewall: false, screenLockMin: 10, patchAgeDays: 41, jailbroken: false },
    "mbp-mei": { id: "mbp-mei", owner: "mei", os: "macos", managed: true, diskEncrypted: true, edr: true, firewall: true, screenLockMin: 5, patchAgeDays: 12, jailbroken: false },
    "xps-lena": { id: "xps-lena", owner: "lena", os: "windows", managed: true, diskEncrypted: true, edr: true, firewall: true, screenLockMin: 5, patchAgeDays: 20, jailbroken: false },
    "byod-sam": { id: "byod-sam", owner: "sam", os: "macos", managed: false, diskEncrypted: true, edr: false, firewall: true, screenLockMin: 15, patchAgeDays: 70, jailbroken: false },
    "mbp-noah": { id: "mbp-noah", owner: "noah", os: "macos", managed: true, diskEncrypted: true, edr: true, firewall: true, screenLockMin: 3, patchAgeDays: 3, jailbroken: false },
  },
};
export const CONNECTORS = {
  grafana: { region: "ap-south-1", lat: 19.1, lon: 72.9 }, gitlab: { region: "eu-central-1", lat: 50.1, lon: 8.7 },
  "prod-db": { region: "ap-south-1", lat: 19.1, lon: 72.9 }, "k8s-api": { region: "ap-southeast-1", lat: 1.3, lon: 103.8 },
  payroll: { region: "eu-central-1", lat: 50.1, lon: 8.7 }, wiki: { region: "us-east-1", lat: 39.0, lon: -77.5 },
};
export const deviceOf = (user) => Object.values(DIRECTORY.devices).find((d) => d.owner === user)?.id;
