---
name: hebrah
version: 0.1.5
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

### Step 1 — Create your agent account

**Via MCP (recommended — Cursor, Claude Code, Codex, OpenCode):**

MCP server: `https://mcp.hebrah.com/mcp`

```
hebrah_create_account orgName="my-research-agent" inviteEmail="you@example.com"
```

Response:

```json
{
  "orgId": "uuid",
  "apiKey": "hb_conn_a1b2c3d4...  (one-time, save now)",
  "trial": {
    "credits": { "queries": 100, "egressBytes": 1073741824 },
    "expiresAt": "2026-09-22T..."
  },
  "mcpEndpointUrl": "https://mcp.hebrah.com/mcp"
}
```

**Via CLI (works in any terminal):**

```bash
npm install -g @hebrah/cli
hebrah signup --name "my-research-agent" --email "you@example.com"
# Saves credentials to ~/.hebrah/credentials (mode 0600)
# $1 free credit automatically applied
```

### Step 2 — Discover available targets

```bash
hebrah discover
```

```
TARGET                                  CONNECTOR    LABEL                              PACK        HEALTH
postgresql://demo-audit.hebrah.com      postgres     Audit ledger (GL evidence)         audit       healthy
sftp://demo-sftp.hebrah.com             sftp         Settlement reconciliation files    fintech     healthy
https://demo-fhir.hebrah.com            fhir         Synthetic EHR (FHIR R4)            healthcare  healthy
https://demo-rest.hebrah.com            http_rest    Public REST research endpoints     developer   healthy
sqlite://demo-research.db               sqlite       Local research DB                  developer   healthy
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
hebrah signup              # creates account
hebrah discover            # lists targets
hebrah connect <target>    # opens connection
hebrah query <conn>        # executes query
hebrah audit <conn>        # shows audit events
hebrah audit export <conn> # exports as JSON
hebrah revoke <conn>       # closes connection
hebrah whoami              # shows account + balance
hebrah usage               # shows metering
```

## Pricing (Monid-style metered)

| Tier | Price | Includes |
|---|---|---|
| **Trial** | $0 | $1 free credit, 100 queries, 1 GB egress, 7-day TTL |
| **Personal** | usage-based | $0.005/query, $0.08/GB egress, no monthly fee |
| **Pro** | $99/mo + usage | 10k queries/mo included, $0.003/query after, 50 GB egress |
| **Pay-as-you-go** | top up via Stripe | No monthly fee, just balance |

No subscriptions. No per-connector fees. No tiered feature gates. Add credit via
Stripe anytime at [hebrah.com/pricing](https://hebrah.com/pricing).

## What you CAN do

- Create an agent account in 90 seconds with $1 trial credit
- Connect to any of 5 demo targets instantly (Postgres, SFTP, FHIR, HTTP/REST, SQLite)
- Run scoped queries with audit-trail evidence
- Verify audit hash chain integrity
- Export audit logs as tamper-evident JSON
- Revoke any connection instantly
- Track cost per query in real time

## What you CANNOT do (yet — Wave 2+)

- Connect to a customer's own private infrastructure (requires relay enrollment)
- Production WireGuard data path (use container tier)
- Write to data sources (read-only)
- HIPAA/BAA compliant health data (Wave 3)
- SOC 2 Type II attested (Wave 2/3)
- Approval-gated writes (Wave 3)

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