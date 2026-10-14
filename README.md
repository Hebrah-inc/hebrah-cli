# @hebrah/cli

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Node 22+](https://img.shields.io/badge/node-%3E%3D22-blueviolet)](./package.json)
[![npm](https://img.shields.io/npm/v/@hebrah/cli)](https://www.npmjs.com/package/@hebrah/cli)

The terminal-native CLI for **Hebrah** — Isolated Health Environments & credential-blind data layer for AI agents.

Install:

```bash
npm install -g @hebrah/cli
hebrah signup --name "clinic-agent" --headless   # 90 seconds, $5 free trial credit, no card
```

## Commands

| Command | Purpose |
|---|---|
| `hebrah signup` | Create a new agent account ($5.00 trial credit) |
| `hebrah login` | Authenticate via browser loopback, device code, or API key (`hb_conn_*` / `hb_pat_*`) |
| `hebrah logout` | Remove local credentials |
| `hebrah whoami` | Show account info, API endpoint, default environment, and balance |
| `hebrah usage` | Show metering for current period |
| `hebrah env list` | List isolated clinic environments |
| `hebrah env create` | Provision an isolated clinic environment (FHIR R4 + HL7 v2 + DB addons) |
| `hebrah env connect <env_id>` | Attach agent to an existing isolated clinic environment and set default |
| `hebrah env status [env_id]` | Show environment details, endpoints, DB modules, and connected agents |
| `hebrah env query [env_id] "<sql>"` | Execute credential-blind SQL query against attached DB module |
| `hebrah env scenario [env_id] --type <t>` | Trigger synthetic clinical EHR scenario (HL7 v2 / FHIR) |
| `hebrah env wireguard [env_id]` | Export WireGuard VPN config (mode 0600) for developer GUI (DBeaver/TablePlus) |
| `hebrah discover` | List available connector targets |
| `hebrah inspect <target>` | Show scope grammar for a target |
| `hebrah packs` | List connector packs |
| `hebrah connect <target>` | Open a scoped connection |
| `hebrah list` | List active connections |
| `hebrah status <conn>` | Show connection status |
| `hebrah revoke <conn>` | Close a connection |
| `hebrah query <conn>` | Execute query through connection |
| `hebrah audit <conn>` | Show audit events |
| `hebrah audit verify <conn>` | Verify hash chain |
| `hebrah audit export <conn>` | Export hash-chained audit log |
| `hebrah topup` | Add credit via Stripe Checkout |
| `hebrah skill` | Print the SKILL.md |
| `hebrah help` | Show help |
| `hebrah version` | Show version |

## Isolated Clinic Environment Onboarding

```bash
npm install -g @hebrah/cli

# Option A: Connect to an existing account & clinic environment via browser
hebrah login --env-id <environment_id>

# Option B: Connect non-interactively with a token from the dashboard
hebrah login --key hb_pat_... --env-id <environment_id>

# Option C: Headless agent self-signup ($5.00 free credit)
hebrah signup --name "clinic-agent" --headless
hebrah env create --name "Memorial Hospital Integration" --clinic hospital_system --addons postgres

# Query attached PostgreSQL 16 credential-blind
hebrah env query "SELECT id, first_name, last_name, primary_diagnosis FROM patients LIMIT 5"
```

## Output formats

Every command supports `--json` for machine-readable output:

```bash
hebrah env status --json
hebrah env query "SELECT COUNT(*) FROM patients" --json
hebrah usage --json
```

## Config

- **Credentials:** `~/.hebrah/credentials` (mode `0600`, symlink-protected, origin-pinned)
- **Env override:** `HEBRAH_API_KEY=hb_conn_*` (or `hb_pat_*`)
- **Self-hosted / Staging:** `hebrah login --app-url https://... --api-url https://...` (persisted automatically)

## Build

```bash
pnpm install
pnpm build
pnpm test
```

## Related

- [hebrah.com/SKILL.md](https://hebrah.com/SKILL.md) — public SKILL.md
- [hebrah.com](https://hebrah.com) — marketing site
- [@hebrah/sdk](https://www.npmjs.com/package/@hebrah/sdk) — official Node.js SDK
- [github.com/Hebrah-inc](https://github.com/Hebrah-inc) — official GitHub organization

## License

MIT