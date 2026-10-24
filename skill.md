---
name: hebrah
version: 0.4.6
description: Isolated Health Environments & credential-blind clinical data connections for AI agents. Use Hebrah when the task requires connecting to a clinic environment (FHIR R4, HL7 v2 WebSocket, DICOMweb PACS, X12 EDI, Postgres, SQLite, Qdrant, Neo4j), consulting the isolated Environment AI Studio, or querying Open-Data Clinical & Imaging Enrichment Packs without receiving raw database credentials.
---

# Hebrah — Isolated Health Environments for AI Agents

## 3-Step Agent Onboarding (90 seconds)

### Step 1 — Install or Upgrade `@hebrah/cli` (v0.4.6+)

```bash
npm install -g @hebrah/cli@latest
```

### Step 2 — Check Existing Credentials or Authenticate

Check the **4-tier detection ladder** first:
1. **Environment Variable**: `$HEBRAH_API_KEY`
2. **Global CLI Credentials**: `~/.hebrah/credentials` (JSON with `apiKey`, `apiUrl`, `defaultEnvId`, mode `0600`)
3. **Project Config**: `.hebrah/credentials` or `.env` in the repo root
4. **Editor MCP Config**: `~/.cursor/mcp.json`, `~/.claude/mcp.json`, etc.

If no credentials exist, choose one of the **3 authentication paths**:

#### Path A — Interactive Browser Login (Recommended when a human user is at their machine)
Opens the browser to `/cli/authorize` and automatically persists `apiKey`, `apiUrl`, and `defaultEnvId` to `~/.hebrah/credentials`:

```bash
# Connect to a specific clinic environment (pass --app-url if using staging/self-hosted):
hebrah login --app-url https://app.hebrah.com --env-id <ENV_ID>

# Or general workspace login:
hebrah login
```

> **Headless / SSH / Container Note**: Use `hebrah login --headless` for RFC 8628 Device Code flow, or ask the user for a token using **Path B**.

#### Path B — Direct Token Login (`hb_conn_*`, `hb_pat_*`, `hb_live_*`, `hb_test_*`)
If the user pastes an API key or Personal Access Token from the **Agents & SDKs** tab of their environment, pipe it via `--key-stdin` (so secrets never appear in `ps aux`):

```bash
printf '%s\n' "$HEBRAH_TOKEN" | hebrah login --key-stdin --app-url https://app.hebrah.com --env-id <ENV_ID>
```

#### Canonical Production Endpoints
- **Dashboard & Claim Portal**: `https://app.hebrah.com`
- **Control Plane REST API**: `https://api.hebrah.com`
- **Hosted Streamable HTTP MCP**: `https://mcp.hebrah.com/mcp`

#### Path C — Autonomous $5 Trial Signup (No card required)
If the user wants you to spin up a brand-new workspace with **$5.00 free credit** (1,000 queries, 50 MB egress, 14-day TTL):

```bash
hebrah signup \
  --name "clinic-integration-agent" \
  --email "developer@yourcompany.com"
```
*(Note: Registration Shield blocks disposable and dummy domains like `@example.com` or `@test.com`; ask the user for their real work/corporate email and share the returned `claimUrl` so they can claim ownership).*

---

### Step 3 — Connect to the Clinic Environment & Query Data

Once authenticated, bind and verify the target clinic environment:

```bash
# 1. Connect to the target clinic environment (sets defaultEnvId in ~/.hebrah/credentials & logs agent.connected)
hebrah env connect <ENV_ID>

# 2. Inspect environment status, FHIR/HL7/DICOM/EDI endpoints, and attached Database Modules
hebrah env info <ENV_ID>

# 3. Consult the isolated Per-Environment GCP AI Studio (with 3-layer anti-skill lock & provenance citations)
hebrah env studio <ENV_ID> "Join our patients with PubMed RCT PICO evidence and show CDS Hooks 2.0 cards"

# 4. Inspect or search the Open-Data Clinical Knowledge & DICOM Imaging Enrichment Packs
hebrah env open-data <ENV_ID> --search "sepsis"

# 5. Run credential-blind SQL queries against the environment's PostgreSQL / SQLite schema
hebrah env query <ENV_ID> --sql "SELECT id, mrn, first_name, last_name, dob, gender, status FROM patients LIMIT 10"

# 6. Trigger a synthetic clinical scenario (e.g. admit_patient, lab_result_critical, vital_alert, med_order, discharge)
hebrah env trigger <ENV_ID> --scenario vital_alert

# 7. Stream live environment activity logs
hebrah env logs <ENV_ID>
```

## CLI Command Summary (`@hebrah/cli` v0.4.6)

```bash
hebrah login [--app-url <url>] [--api-url <url>] [--env-id <id>] [--key-stdin] [--headless]
hebrah signup --name <org> --email <work-email> [--app-url <url>] [--api-url <url>] [--env-id <id>]
hebrah whoami                          # Show authenticated org, API endpoint, default environment, and wallet balance
hebrah env list                        # List isolated health environments
hebrah env create --name "Cardiology"  # Provision a new isolated clinic environment
hebrah env architect "<prompt>"        # Design or auto-provision via Conversational Environment Architect
hebrah env connect <env_id>            # Bind CLI/agent to environment & print endpoints
hebrah env info [env_id]               # Inspect environment endpoints & attached database modules
hebrah env studio [env_id] "<prompt>"  # Consult isolated Per-Environment GCP AI Studio
hebrah env open-data [env_id]          # Inspect/search Open-Data Clinical & DICOM Enrichment Packs
hebrah env tables [env_id]             # List isolated database tables and row counts
hebrah env patients [env_id]           # List synthetic patients with clinical filters
hebrah env admit [env_id] --count <n>  # Dynamically admit synthetic patients into cohort
hebrah env query [env_id] --sql "..."  # Run credential-blind SQL query (SELECT + INSERT INTO app_outcomes)
hebrah env trigger [env_id] --scenario <name>
hebrah env logs [env_id]               # View environment activity & audit logs
hebrah env wireguard [env_id]          # Export WireGuard VPN config (0600 permissions) for human DB GUIs
hebrah discover                        # List catalog data targets
hebrah connect <target> --scopes <...> # Open scoped connection handle
hebrah query <conn_id> --sql "..."     # Execute scoped query
hebrah audit <conn_id> --verify        # Verify SHA-256 hash-chained audit trail
```