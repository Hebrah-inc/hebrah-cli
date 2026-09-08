# @hebrah/cli

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Node 22+](https://img.shields.io/badge/node-%3E%3D22-blueviolet)](./package.json)
[![npm](https://img.shields.io/npm/v/@hebrah/cli)](https://www.npmjs.com/package/@hebrah/cli)

The terminal-native CLI for **Hebrah** — the data layer for AI agents.

Install:

```bash
npm install -g @hebrah/cli
hebrah signup        # 90 seconds, $1 trial credit, no card
```

> Companion to the [Wave 1 strategy doc](https://github.com/Hebrah-inc/hebrah-strategy-docs/blob/main/documentation/hebrah-strategy-2026-09-cli.md) in the `hebrah-strategy-docs` repo.

## Commands

| Command | Purpose |
|---|---|
| `hebrah signup` | Create a new agent account |
| `hebrah login` | Load existing credentials |
| `hebrah logout` | Remove local credentials |
| `hebrah whoami` | Show account info + balance |
| `hebrah usage` | Show metering for current period |
| `hebrah discover` | List available targets |
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
| `hebrah skill` | Print the SKILL.md |
| `hebrah help` | Show help |
| `hebrah version` | Show version |

## 90-second onboarding

```bash
npm install -g @hebrah/cli
hebrah signup --name "research-agent" --email "you@example.com"
hebrah discover
hebrah connect postgresql://demo-audit.hebrah.com \
  --scopes gl:read,period:2025-Q4,accounts:1000-3999
hebrah query <conn_id> --sql "SELECT * FROM gl LIMIT 10"
hebrah audit <conn_id> --verify
hebrah audit <conn_id> --export json > audit.json
hebrah revoke <conn_id>
```

## Output formats

Every command supports `--json` for machine-readable output:

```bash
hebrah discover --json
hebrah query <conn> --sql "..." --json
hebrah usage --json
```

## Config

- **Credentials:** `~/.hebrah/credentials` (mode 0600)
- **Env override:** `HEBRAH_API_KEY=hb_conn_*`
- **Self-hosted:** `HEBRAH_API_URL=https://api.staging.hebrah.com`

## Build

```bash
pnpm install
pnpm build
pnpm test
```

## Related

- [hebrah.com/SKILL.md](https://hebrah.com/SKILL.md) — public SKILL.md (Wave 1 onboarding doc)
- [hebrah.com](https://hebrah.com) — marketing site
- [@hebrah/sdk](https://www.npmjs.com/package/@hebrah/sdk) — official Node.js SDK
- [github.com/Hebrah-inc](https://github.com/Hebrah-inc) — org with strategy docs and demos

## License

MIT