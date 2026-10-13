---
name: hebrah
version: 0.2.0
description: Scoped, audited, revocable connections to private data for AI agents. Use Hebrah when the task requires private data the user owns but you can't easily reach — databases, SFTP, FHIR systems, workspace APIs — without receiving the credential.
---

# Hebrah — the data layer for AI agents

## When to use Hebrah

Use Hebrah when your task requires **private data the user owns but you can't easily reach**:

- A research agent pulling from a customer database the user has access to
- A workflow agent querying a workspace (Notion, Airtable) the user manages
- A clinical agent reading patient records from an EHR system
- An audit agent pulling GL entries from a financial system
- An indie developer's local SQLite research DB

Do **NOT** use Hebrah when:

- The user can hand you the data directly (just read the file)
- The data is a public API you can call directly (use a generic HTTP tool)
- The task doesn't require scoped data access (a calculator, a chat model)
- You need real-time streaming (Hebrah is query-based, not subscription-based)

## 5-step onboarding (90 seconds)

### Step 1 — Check Existing Credentials or Create Account

Before creating a new account, check the **detection ladder** to see if your user already has credentials configured on this machine:

1. **Environment Variable:** Check if `$HEBRAH_API_KEY` is set.
2. **Global CLI Credentials:** Check if `~/.hebrah/credentials` exists (JSON with `apiKey`, mode `0600`).
3. **Project Config:** Check if `.hebrah/credentials` or `.env` in the repo root has `HEBRAH_API_KEY`.
4. **Editor MCP Config:** Check if your editor MCP config (`~/.cursor/mcp.json`, etc.) includes `Authorization: Bearer hb_conn_*`.

**If credentials exist:** You are already authenticated! Proceed to Step 2.

**If no credentials exist, choose your trajectory:**

- **Connect existing Hebrah account:**
  - On local desktop: run `hebrah login` (launches browser approval on `app.hebrah.com`).
  - On remote SSH / Docker: run `hebrah login --headless` (RFC 8628 device flow via `app.hebrah.com/device`).
- **Start autonomous $5 trial (no card required):**

**Via MCP (recommended — Cursor, Claude Code, Codex, OpenCode):**

MCP server: `https://mcp.hebrah.com/mcp`

```
hebrah_create_account orgName="clinic-research-agent" inviteEmail="developer@hospital.org"
```

Response:

```json
{
  "orgId": "uuid",
  "apiKey": "hb_conn_a1b2c3d4...  (one-time, save now)",
  "claimUrl": "https://app.hebrah.com/claim-org/...",
  "inviteEmail": "developer@hospital.org",
  "trial": {
    "credits": { "queries": 1000, "egressBytes": 50000000 },
    "expiresAt": "2026-10-27T..."
  },
  "mcpEndpointUrl": "https://mcp.hebrah.com/mcp"
}
```

Trial: **$5 credit — no card required. 1,000 queries, 50 MB egress, 14-day TTL.** An invitation is emailed to `inviteEmail` (generic test domains like `@example.com` or disposable emails are blocked by the registration shield; use your corporate or work email). Present the `claimUrl` to your user to claim ownership and configure auto-reload billing.

**Via CLI (works in any terminal):**

```bash
npm install -g @hebrah/cli

# Create a new trial account:
hebrah signup --name "clinic-research-agent" --email "developer@hospital.org"
# Saves credentials to ~/.hebrah/credentials (mode 0600)
# $5 free credit automatically applied

# Or connect an existing workspace:
hebrah login             # Desktop: opens browser consent on app.hebrah.com
hebrah login --headless  # Remote / SSH: generates device code for app.hebrah.com/device
```

### Step 2 — Discover available targets

```bash
hebrah discover
```

```
TARGET                                  CONNECTOR    LABEL                              PACK        HEALTH
https://demo-fhir.hebrah.com/fhir       fhir         Synthetic EHR (FHIR R4)            healthcare  healthy
wss://demo-hl7.hebrah.com/ws/alerts     hl7          Real-time ADT clinical feed        healthcare  healthy
postgresql://demo-clinic.hebrah.com     postgres     Clinic relational DB (PG16)        database    healthy
sqlite://demo-clinic.db                 sqlite       Clinic embedded SQLite store       database    healthy
https://demo-qdrant.hebrah.com:6333     qdrant       Clinical embedding vector store    database    healthy
bolt://demo-neo4j.hebrah.com:7687       neo4j        Medical ontology graph (SNOMED)    database    healthy
```
`hebrah discover` lists all 55 targets across 11 packs — plus live account connectors connected with read-only credentials.
```

```bash
hebrah inspect postgresql://demo-audit.hebrah.com
```

```
Target:    postgresql://demo-audit.hebrah.com:5432/audit
Connector: postgres
Tables:    [gl]
Scopes:    gl:read, period:<YYYY-QN>, accounts:<MIN>-<MAX>
Tiers:     container, vm
Writes:    false
Example:   --scopes gl:read,period:2025-Q4,accounts:1000-3999
```

### Step 3 — Connect to a target

```bash
hebrah connect postgresql://demo-audit.hebrah.com \
  --scopes gl:read,period:2025-Q4,accounts:1000-3999 \
  --ttl 3600
```

```json
{
  "connectionId": "conn_uuid",
  "target": "postgresql://demo-audit.hebrah.com:5432/audit",
  "scopes": ["gl:read", "period:2025-Q4", "accounts:1000-3999"],
  "tier": "container",
  "ttl": 3600,
  "ttlExpiresAt": "2026-09-15T..."
}
```

### Step 4 — Query through the connection

```bash
hebrah query conn_uuid --sql "SELECT * FROM gl LIMIT 10"
```

```json
{
  "rows": [...],
  "auditEventId": "audit_uuid",
  "bytesEgressed": 1284,
  "cost": { "queries": 1, "egressBytes": 1284, "totalCents": 0 },
  "scopeApplied": "period:2025-Q4, accounts:1000-3999"
}
```

The query is **server-side scope-rewritten** before execution. `SELECT *`
returns only in-scope rows. Tampering with the scope is impossible.

### Step 5 — Export the audit trail

```bash
hebrah audit conn_uuid --export json > audit.json
hebrah audit conn_uuid --verify
# { "verified": true, "eventsChecked": 42, "genesisHash": "..." }
```

The export is **hash-chained**: each audit event includes the SHA-256 hash
of the previous event. Modifying any row breaks the chain.

## MCP install

Add to your MCP config (`~/.cursor/mcp.json`, `~/.claude/mcp.json`, etc.):

```json
{
  "mcpServers": {
    "hebrah": {
      "type": "http",
      "url": "https://mcp.hebrah.com/mcp",
      "headers": { "Authorization": "Bearer hb_conn_YOUR_KEY" }
    }
  }
}
```

Restart your MCP client. The 5 tools become available:

| Tool | Purpose |
|---|---|
| `hebrah_create_account` | Self-serve signup + $1 trial |
| `hebrah_discover_targets` | List available targets |
| `hebrah_connect` | Open scoped connection |
| `hebrah_query` | Execute query through connection |
| `hebrah_audit_export` | Export hash-chained audit log |

## CLI install

```bash
npm install -g @hebrah/cli
hebrah signup                    # creates account
hebrah discover                  # lists targets
hebrah connect <target>          # opens connection
hebrah query <conn>              # executes query
hebrah audit <conn>              # shows audit events
hebrah audit export <conn>       # exports as JSON
hebrah revoke <conn>             # closes connection
hebrah relay enroll --target <pg-uri> --scopes <...>   # mint enrollment token
hebrah relay list                # list customer-side relays
hebrah relay status <relay_id>   # show one relay
hebrah relay revoke <relay_id>   # cut off a relay
hebrah whoami                    # shows account + balance
hebrah usage                     # shows metering
```

## Pricing (Monid-style metered)

| Tier | Price | Includes |
|---|---|---|
| **Trial** | $0 | $5 free credit, 1,000 queries, 50 MB egress, 14-day TTL |
| **Personal** | usage-based | $0.005/query, $0.08/GB egress, no monthly fee |
| **Pro** | $99/mo + usage | 10k queries/mo included, $0.003/query after, 50 GB egress |
| **Pay-as-you-go** | top up via Stripe | No monthly fee, just balance |

No subscriptions. No per-connector fees. No tiered feature gates. Add credit via
Stripe anytime at [hebrah.com/pricing](https://hebrah.com/pricing).

## What you CAN do

- Create an agent account in 90 seconds with $5 trial credit (1,000 queries, 50 MB egress, 14 days)
- Spin up and connect to Isolated Health Environments per clinic with realistic synthetic EHR data (FHIR R4 REST, HL7 v2 WebSocket stream, X12 EDI)
- Query attached database pack modules (PostgreSQL 16, SQLite, Qdrant Vector DB, Neo4j Graph DB) via credential-blind handles
- Allow human team members to connect to environment databases using desktop tools (DBeaver, TablePlus) over secure WireGuard VPN
- Run scoped queries with audit-trail evidence and actor attribution (agent, human_user, sdk_integration)
- Verify cryptographic audit hash chain integrity
- Export audit logs as tamper-evident JSON
- Revoke any connection or pause/destroy any environment instantly
- Track hourly environment runtime and per-query costs in real time

## What you CANNOT do

- Access real PHI or live clinical EHR credentials (Hebrah environments are synthetic-first to eliminate compliance risks)
- Direct root database credentials for agents (agents query exclusively through credential-blind handles; human developers access DBs over WireGuard)
- Connect with disposable or generic spam email addresses (registration shield enforces valid corporate/work email)

## Rules for agents

1. **Always start with `discover`** before connecting — the scope grammar varies per target.
2. **Inspect scope before querying** — `hebrah inspect <target>` shows allowed tables/periods/accounts.
3. **Report cost on each query** — `cost` is in the response; surface it to the user.
4. **Don't share your API key** — each agent account is single-purpose.
5. **Revoke on task completion** — ephemeral by design.
6. **Export audit on demand** — the audit trail is your evidence trail.
7. **Use container tier by default** — VM tier is for regulated workloads (Wave 2+).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `401 Unauthorized` | Check API key in `~/.hebrah/credentials`; re-run `hebrah login` |
| `403 Origin not allowed` | (For browser flows) Origin must be in `HEADLESS_SIGNUP_CORS_ORIGINS` allowlist |
| `402 quota exceeded` | Add credit via `hebrah topup` or visit hebrah.com/pricing |
| `429 rate limited` | 3 account creations / IP / 24h; 50 / hour global — back off |
| `connection.scope_violation` | The query asked for out-of-scope rows; re-check scope grammar |
| `audit.verify failed` | Hash chain broken — likely tampering or replication lag; re-export from source |
| `connection.revoked` (410) | Connection TTL expired or was explicitly revoked; open a new one |

## Support

- Docs: https://hebrah.com/docs
- Status: https://status.hebrah.com
- Issues: https://github.com/hebrah-inc/hebrah-cli/issues
- Email: hello@hebrah.com

## Trust

- **Hash-chained audit** — every event is SHA-256 chained to the previous one
- **Server-side scope rewrite** — `OR true` cannot widen scope
- **Read-only transactions** — Postgres connector runs in `READ ONLY` mode
- **No credential to agent** — agents never see data-source credentials
- **Instant revocation** — `hebrah revoke` closes the connection in milliseconds

## What Hebrah is NOT claiming (yet)

- SOC 2 Type II attestation (Wave 2)
- HIPAA + BAA (Wave 3)
- Production WireGuard data path (Wave 2)
- Approval-gated scoped writes (Wave 3)
- Sub-100ms p99 query latency (best-effort, not SLA)