# Prism ZTNA — Usage

## Install

```bash
npm install github:krishyaa06/prism-ztna
# or run the CLI directly
npx github:krishyaa06/prism-ztna --help
```

## JavaScript API

```js
import { Broker, Mesh, Policy, posture } from "prism-ztna";

const policy = `
app prod-db  host "10.0.4.12:5432"  tags [prod]
deny  "geo"      *         when geo.country in ["KP", "IR"]
deny  "posture"  tag:prod  when device.tier != "trusted"
allow "sre"      tag:prod  when "sre" in user.groups and device.score >= 80 require mfa within 15m`;

const zt = new Broker({ policy, directory, mesh: new Mesh({ connectors }) });
const { token, sid } = zt.login("riya", "mbp-riya");          // posture-checked, device-bound token

const d = zt.access(token, "prod-db", { deviceId: "mbp-riya" });
d.effect;   // "allow" | "deny" | "challenge"
d.rule;     // "sre"
d.trace;    // every rule and comparison, with the values it saw
d.route;    // { path: ["bom"], rtt: 1.1 }

zt.stepUp(sid);                       // after WebAuthn / TOTP
zt.revokeDevice("mbp-riya", "lost");  // kill every session on a device
zt.verifyAudit();                     // { ok: true, entries, head }

new Policy(policy).lint();            // unknown targets, unreachable apps, unconditional rules
```

| Export | What it does |
|---|---|
| `new Policy(src)` · `.decide(ctx, app)` · `.lint()` · `.apps` · `.rules` · `.version` | Compile, evaluate and lint a policy |
| `parse(src)` · `tokenize(src)` · `evaluate(node, ctx, trace)` · `PolicyError` (`line`, `col`) | Language internals |
| `posture(device)` · `CHECKS` | Device posture score, tier and failed checks |
| `new Keyring(secret)` · `.rotate()` · `sign(claims, ring)` · `verify(token, ring, { now, device, aud })` · `decode` · `deviceThumb` | Session tokens |
| `new Mesh({ pops, connectors })` · `.route(geo, app)` · `.setPop(id, up)` · `km` · `rttMs` | PoP mesh and routing |
| `new Broker({ policy, directory, mesh, ttl, minScore })` · `login` · `access` · `stepUp` · `revoke` · `revokeDevice` · `explain` · `setPolicy` · `verifyAudit` · `on(fn)` | The access broker |
| `createProxy(broker, { upstreams, adminKey })` from `src/node/proxy.js` | Identity-aware HTTP reverse proxy |

## CLI

```bash
$ npx github:krishyaa06/prism-ztna demo
$ npx github:krishyaa06/prism-ztna lint examples/policy.ztna
$ npx github:krishyaa06/prism-ztna eval --user arjun --app prod-db
$ npx github:krishyaa06/prism-ztna posture
$ npx github:krishyaa06/prism-ztna route --user riya --app gitlab --down fra
$ npx github:krishyaa06/prism-ztna serve --port 8080
```

| Command | Description |
|---|---|
| `ztna lint [file.ztna]` | Rules table and static warnings |
| `ztna eval [file.ztna] --user --app [--mfa 5m --country IN --hour 14 --device]` | Explain one decision rule by rule |
| `ztna posture [--device id]` | Posture checks and score |
| `ztna route --user --app [--down bom,fra]` | Path through the PoP mesh |
| `ztna token --user` | Issue and decode a session token |
| `ztna demo` | End-to-end scenario with audit verification |
| `ztna serve [--port 8080] [file.ztna]` | Proxy in front of demo apps (`/auth/login`, `/auth/mfa`, `/_audit`, `/_policy`) |

## Live simulator

Open [https://krishyaa06.github.io/prism-ztna/](https://krishyaa06.github.io/prism-ztna/) or serve the repo root locally (`npx serve .`). The simulator imports the same modules from `src/`.
