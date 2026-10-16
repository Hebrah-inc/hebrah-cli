// `hebrah env` — manage isolated clinic environments.
//
// Subcommands:
//   hebrah env list [--all] [--json]
//     List all active isolated clinic environments for the current org.
//
//   hebrah env create --name <name> [--clinic <type>] [--cohort <cohort>] [--addons <addons>] [--patients <n>] [--beds <n>] [--json]
//     Provision a dedicated, compliant isolated health environment with synthetic EHR + attachable DBs.
//
//   hebrah env connect <id> [--name <agent-name>] [--json]
//     Attach this agent to an isolated clinic environment and set it as the default environment.
//
//   hebrah env status [id] [--json]
//     Show full environment details, clinical endpoints, attached DBs, and connected agents.
//
//   hebrah env pause [id] [--json]
//     Pause an environment to halt hourly resource burn.
//
//   hebrah env resume [id] [--json]
//     Resume a paused environment.
//
//   hebrah env destroy <id> [--yes] [--json]
//     Tear down an environment and release its resources.
//
//   hebrah env query [id] "<sql>" [--addon <postgres>] [--json]
//     Execute a credential-blind query against an attached database module handle.
//
//   hebrah env wireguard [id] [--out <file>] [--reveal-private-key] [--json]
//     Export or print WireGuard mesh VPN configuration for human developer GUI access (DBeaver, TablePlus).
//
//   hebrah env scenario [id] --type <scenario> [--patient-id <id>] [--notes <notes>] [--json]
//     Trigger a synthetic clinical EHR scenario (admit_patient, transfer_patient, discharge_patient, abnormal_lab_alert).
//
//   hebrah env db-proxy [id] [--port <port>] [--addon <addon>] [--json]
//     Display connection coordinates and guidance for human developer database GUIs over WireGuard.

import { parseArgs } from 'node:util';
import { writeFileSync, existsSync, lstatSync, chmodSync } from 'node:fs';
import { hostname, platform } from 'node:os';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { api, safeId } from '../api/client.js';
import { loadCredentials, updateCredentials } from '../config/credentials.js';
import { normalizeWireguardConfig } from './db.js';
import {
  success,
  info,
  warn,
  error,
  json,
  table,
  kv,
  bold,
  dim,
  green,
  red,
  cyan,
  yellow,
  formatBytes,
  formatCents
} from '../output/format.js';
import { getArgv } from '../util/args.js';

function resolveEnvId(explicitId?: string): string | undefined {
  if (explicitId && explicitId.trim().length > 0) {
    return explicitId.trim();
  }
  if (process.env.HEBRAH_ENV_ID && process.env.HEBRAH_ENV_ID.trim().length > 0) {
    return process.env.HEBRAH_ENV_ID.trim();
  }
  return loadCredentials()?.defaultEnvId;
}

function redactWireguardPrivateKey(configText: string): string {
  return configText.replace(
    /^(\s*PrivateKey\s*=\s*).+$/gim,
    '$1<redacted — use --out ./wg.conf or --reveal-private-key>'
  );
}

// ---------------------------------------------------------------------------
// Types matching hebrah-api environments endpoints
// ---------------------------------------------------------------------------

export interface EnvironmentSummary {
  id: string;
  org_id: string;
  name: string;
  clinic_type: string;
  patient_cohort: string;
  status: string;
  addons: string[];
  patient_count: number;
  bed_count: number;
  endpoints: {
    fhir?: string;
    hl7_ws?: string;
    x12?: string;
    [key: string]: string | undefined;
  };
  wireguard_ip: string | null;
  queries_run: number;
  bytes_egressed: number;
  hourly_rate_cents: number;
  total_cost_cents: number;
  connected_agents_count: number;
  last_active_at: string | null;
  created_at: string;
}

export interface EnvironmentDetail extends EnvironmentSummary {
  connection_instructions: Record<string, unknown>;
  database_modules: Array<{
    type: string;
    status: string;
    port: number;
    size_mb: number;
    tables_count: number;
  }>;
  connected_agents: Array<{
    agent_id: string;
    name: string;
    connected_at: string;
  }>;
}

export interface DbQueryResult {
  rows: Array<Record<string, unknown>>;
  row_count: number;
  bytes_egressed: number;
  duration_ms: number;
  sql_executed: string;
}

export interface WireguardConfigResult {
  environment_id: string;
  client_ip: string;
  server_endpoint: string;
  config_text: string;
}

export interface ClinicScenarioResult {
  ok: boolean;
  scenario: string;
  hl7_message: string;
  websocket_broadcast: boolean;
}

// ---------------------------------------------------------------------------
// Subcommand dispatch
// ---------------------------------------------------------------------------

export default async function env(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const sub = argv.find((a) => !a.startsWith('-')) ?? args[0];
  const subIdx = sub ? argv.indexOf(sub) : -1;
  const subArgv = subIdx >= 0 ? argv.slice(subIdx + 1) : argv;

  switch (sub) {
    case 'list':
    case 'ls':
      return listEnvs(subArgv, { ...options, _argv: subArgv });
    case 'create':
    case 'new':
      return createEnv(subArgv, { ...options, _argv: subArgv });
    case 'connect':
    case 'attach':
    case 'use':
      return connectEnv(subArgv, { ...options, _argv: subArgv });
    case 'status':
    case 'show':
    case 'get':
      return statusEnv(subArgv, { ...options, _argv: subArgv });
    case 'pause':
      return pauseEnv(subArgv, { ...options, _argv: subArgv });
    case 'resume':
      return resumeEnv(subArgv, { ...options, _argv: subArgv });
    case 'destroy':
    case 'rm':
    case 'delete':
      return destroyEnv(subArgv, { ...options, _argv: subArgv });
    case 'query':
    case 'sql':
      return queryEnv(subArgv, { ...options, _argv: subArgv });
    case 'wireguard':
    case 'wg':
      return wireguardEnv(subArgv, { ...options, _argv: subArgv });
    case 'scenario':
    case 'trigger':
      return scenarioEnv(subArgv, { ...options, _argv: subArgv });
    case 'db-proxy':
    case 'proxy':
      return dbProxyEnv(subArgv, { ...options, _argv: subArgv });
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      showHelp();
      return 0;
    default:
      error(`hebrah env: unknown subcommand "${sub}"`);
      showHelp();
      return 1;
  }
}

function showHelp(): void {
  console.log(`hebrah env — manage isolated clinic environments

Subcommands:
  list (ls)                    List environments for the current org
  create (new)                 Provision a new isolated clinic environment
  connect (attach) <id>        Attach this agent to an environment & set default
  status (show) [id]           Show details, endpoints, and connected agents
  pause [id]                   Pause environment (halts hourly resource charge)
  resume [id]                  Resume a paused environment
  destroy (rm) <id>            Tear down an environment
  query (sql) [id] "<sql>"     Run credential-blind query on attached DB
  wireguard (wg) [id]          Export WireGuard VPN config for GUI access
  scenario [id] --type <type>  Trigger a clinical EHR event (HL7 / FHIR)
  db-proxy [id]                Show developer GUI connection coordinates

Flags (global for subcommands):
  --json                       Emit JSON machine-readable output

Examples:
  hebrah env list
  hebrah env connect 4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94 --name "clinic-agent"
  hebrah env create --name "Pediatric Pilot" --clinic pediatric_specialty --addons postgres,neo4j
  hebrah env query "SELECT * FROM patients LIMIT 5"
  hebrah env wireguard --out ./hebrah-clinic.conf
  hebrah env scenario --type admit_patient --patient-id P-1002
`);
}

// ---------------------------------------------------------------------------
// Subcommand: list
// ---------------------------------------------------------------------------

async function listEnvs(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values } = parseArgs({
    args: argv,
    options: {
      all: { type: 'boolean', short: 'a', default: false },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  try {
    const queryParams: Record<string, string> = {};
    if (values.all) {
      queryParams.include_destroyed = 'true';
    }

    const res = await api.get<EnvironmentSummary[] | { environments: EnvironmentSummary[] }>('/v1/environments', queryParams);
    const envs = Array.isArray(res) ? res : (res.environments ?? []);

    if (values.json) {
      json(envs);
      return 0;
    }

    if (envs.length === 0) {
      console.log(dim('No environments found. Run "hebrah env create" to provision one.'));
      return 0;
    }

    const headers = ['ID', 'NAME', 'CLINIC TYPE', 'STATUS', 'ADD-ONS', 'QUERIES', 'COST'];
    const rows = envs.map((e) => {
      let statusStr = e.status;
      if (e.status === 'active') statusStr = green('active');
      else if (e.status === 'paused') statusStr = yellow('paused');
      else if (e.status === 'destroyed') statusStr = red('destroyed');

      return [
        e.id,
        e.name,
        e.clinic_type,
        statusStr,
        (e.addons ?? []).join(', ') || 'none',
        String(e.queries_run ?? 0),
        formatCents(e.total_cost_cents ?? 0)
      ];
    });

    table(headers, rows);
    console.log();
    console.log(dim(`Total: ${envs.length} environment${envs.length === 1 ? '' : 's'}`));
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: create
// ---------------------------------------------------------------------------

async function createEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values } = parseArgs({
    args: argv,
    options: {
      name: { type: 'string' },
      clinic: { type: 'string' },
      'clinic-type': { type: 'string' },
      type: { type: 'string' },
      cohort: { type: 'string' },
      addons: { type: 'string' },
      db: { type: 'string' },
      patients: { type: 'string' },
      beds: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const name = typeof values.name === 'string' ? values.name : 'Sandbox Clinic';
  const clinicType =
    typeof values['clinic-type'] === 'string'
      ? values['clinic-type']
      : typeof values.clinic === 'string'
        ? values.clinic
        : typeof values.type === 'string'
          ? values.type
          : 'general_clinic';
  const cohort = typeof values.cohort === 'string' ? values.cohort : 'geriatric';
  const rawAddons = typeof values.addons === 'string' ? values.addons : (typeof values.db === 'string' ? values.db : 'postgres');
  const addons = rawAddons.split(',').map((s: string) => s.trim()).filter(Boolean);
  const patientCount = typeof values.patients === 'string' ? parseInt(values.patients, 10) : 25;
  const bedCount = typeof values.beds === 'string' ? parseInt(values.beds, 10) : 40;

  try {
    const created = await api.post<EnvironmentDetail>('/v1/environments', {
      name,
      clinic_type: clinicType,
      patient_cohort: cohort,
      patient_count: patientCount,
      bed_count: bedCount,
      addons
    });

    try {
      updateCredentials({ defaultEnvId: created.id });
    } catch {
      // Ignore if credentials haven't been saved to disk (e.g. env-var only auth)
    }

    if (values.json) {
      json(created);
      return 0;
    }

    success(`Environment provisioned: ${bold(created.name)} (${created.id})`);
    console.log();
    kv([
      ['Environment ID', created.id],
      ['Clinic Type', created.clinic_type],
      ['Patient Cohort', created.patient_cohort],
      ['Synthetic Patients', String(created.patient_count)],
      ['Beds', String(created.bed_count)],
      ['Status', green(created.status)],
      ['Rate', `${formatCents(created.hourly_rate_cents)}/hr`],
      ['Attached DBs', created.addons.join(', ')],
      ['FHIR R4 Endpoint', created.endpoints?.fhir ?? 'n/a'],
      ['HL7 v2 Stream', created.endpoints?.hl7_ws ?? 'n/a'],
      ['WireGuard IP', created.wireguard_ip ?? 'Allocating']
    ]);
    console.log();
    info('Connect your agent using credential-blind query handles: "hebrah env query ' + created.id + ' <sql>"');
    info('Connect your developer GUI (DBeaver/TablePlus) via WireGuard: "hebrah env wireguard ' + created.id + '"');
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: connect
// ---------------------------------------------------------------------------

async function connectEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const rawEnvId = argv.find((a) => !a.startsWith('-'));

  const { values } = parseArgs({
    args: argv.filter((a) => a !== rawEnvId),
    options: {
      name: { type: 'string' },
      'agent-name': { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false,
    strict: false
  });

  const envId = resolveEnvId(rawEnvId);
  if (!envId) {
    error('hebrah env connect: environment_id required');
    console.error('Usage: hebrah env connect <environment_id> [--agent-name <name>] [--json]');
    return 1;
  }

  const agentName =
    typeof values['agent-name'] === 'string'
      ? values['agent-name']
      : typeof values.name === 'string'
        ? values.name
        : process.env.HEBRAH_AGENT_NAME || `hebrah-cli (${hostname()})`;

  try {
    const cleanId = safeId(envId, 'environment_id');
    let detail: EnvironmentDetail;
    try {
      detail = await api.post<EnvironmentDetail>(`/v1/environments/${cleanId}/agents/connect`, {
        agent_name: agentName,
        cli_version: '0.4.1',
        platform: `${platform()}-${hostname()}`
      });
    } catch {
      // Fallback if server hasn't deployed /agents/connect yet
      detail = await api.get<EnvironmentDetail>(`/v1/environments/${cleanId}`);
    }

    try {
      updateCredentials({ defaultEnvId: detail.id });
    } catch {
      // Ignore if credentials file does not exist
    }

    if (values.json) {
      json(detail);
      return 0;
    }

    success(`Connected agent ${bold(agentName)} to environment ${bold(detail.name)} (${detail.id})`);
    console.log();
    kv([
      ['Environment ID', detail.id],
      ['Environment Name', detail.name],
      ['Status', detail.status === 'active' ? green('active') : yellow(detail.status)],
      ['Clinic Type', detail.clinic_type],
      ['Patient Cohort', `${detail.patient_cohort} (${detail.patient_count} patients, ${detail.bed_count} beds)`],
      ['Attached DBs', (detail.addons || []).join(', ') || 'postgres'],
      ['FHIR R4 REST', detail.endpoints?.fhir ?? 'n/a'],
      ['HL7 v2 WebSocket', detail.endpoints?.hl7_ws ?? 'n/a'],
      ['Default Env Saved', green('yes (~/.hebrah/credentials.json)')]
    ]);
    console.log();
    info(`Run a credential-blind SQL query: hebrah env query ${detail.id} "SELECT * FROM patients LIMIT 5"`);
    info(`Trigger an HL7 v2 clinical event: hebrah env scenario ${detail.id} --type admit_patient`);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: status
// ---------------------------------------------------------------------------

async function statusEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const rawEnvId = argv.find((a) => !a.startsWith('-'));

  const { values } = parseArgs({
    args: argv.filter((a) => a !== rawEnvId),
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false,
    strict: false
  });

  const envId = resolveEnvId(rawEnvId);
  if (!envId) {
    error('hebrah env status: environment_id required');
    console.error('Usage: hebrah env status <environment_id> [--json]');
    return 1;
  }

  try {
    const detail = await api.get<EnvironmentDetail>(`/v1/environments/${safeId(envId, 'environment_id')}`);

    if (values.json) {
      json(detail);
      return 0;
    }

    let statusDisplay = detail.status;
    if (detail.status === 'active') statusDisplay = green('active');
    else if (detail.status === 'paused') statusDisplay = yellow('paused');
    else if (detail.status === 'destroyed') statusDisplay = red('destroyed');

    console.log(bold(`Environment: ${detail.name}`));
    console.log();
    kv([
      ['ID', detail.id],
      ['Organization', detail.org_id],
      ['Status', statusDisplay],
      ['Clinic Type', detail.clinic_type],
      ['Patient Cohort', detail.patient_cohort],
      ['Synthetic Records', `${detail.patient_count} patients, ${detail.bed_count} beds`],
      ['Hourly Rate', `${formatCents(detail.hourly_rate_cents)}/hr`],
      ['Total Cost', formatCents(detail.total_cost_cents)],
      ['Queries Executed', String(detail.queries_run)],
      ['Bytes Egressed', formatBytes(detail.bytes_egressed)],
      ['WireGuard IP', detail.wireguard_ip ?? 'None'],
      ['Created At', detail.created_at]
    ]);

    console.log();
    console.log(bold('Clinical Endpoints (Synthetic EHR):'));
    kv([
      ['FHIR R4 REST', detail.endpoints?.fhir ?? 'n/a'],
      ['HL7 v2 WebSocket', detail.endpoints?.hl7_ws ?? 'n/a'],
      ['X12 EDI Stream', detail.endpoints?.x12 ?? 'n/a']
    ], 'gray');

    if (detail.database_modules && detail.database_modules.length > 0) {
      console.log();
      console.log(bold('Attached Database Modules:'));
      for (const db of detail.database_modules) {
        console.log(`  • ${bold(db.type)}: ${green(db.status)} · Port ${db.port} · ${db.size_mb} MB (${db.tables_count} tables)`);
      }
    }

    if (detail.connected_agents && detail.connected_agents.length > 0) {
      console.log();
      console.log(bold('Active AI Agents:'));
      for (const ag of detail.connected_agents) {
        console.log(`  • ${cyan(ag.name)} (${ag.agent_id}) connected at ${ag.connected_at}`);
      }
    }

    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: pause
// ---------------------------------------------------------------------------

async function pauseEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const rawEnvId = argv.find((a) => !a.startsWith('-'));

  const { values } = parseArgs({
    args: argv.filter((a) => a !== rawEnvId),
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false,
    strict: false
  });

  const envId = resolveEnvId(rawEnvId);
  if (!envId) {
    error('hebrah env pause: environment_id required');
    console.error('Usage: hebrah env pause <environment_id>');
    return 1;
  }

  try {
    const updated = await api.post<EnvironmentDetail>(`/v1/environments/${safeId(envId, 'environment_id')}/pause`);

    if (values.json) {
      json(updated);
      return 0;
    }

    success(`Environment ${bold(envId)} paused. Hourly resource charges halted.`);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: resume
// ---------------------------------------------------------------------------

async function resumeEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const rawEnvId = argv.find((a) => !a.startsWith('-'));

  const { values } = parseArgs({
    args: argv.filter((a) => a !== rawEnvId),
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false,
    strict: false
  });

  const envId = resolveEnvId(rawEnvId);
  if (!envId) {
    error('hebrah env resume: environment_id required');
    console.error('Usage: hebrah env resume <environment_id>');
    return 1;
  }

  try {
    const updated = await api.post<EnvironmentDetail>(`/v1/environments/${safeId(envId, 'environment_id')}/resume`);

    if (values.json) {
      json(updated);
      return 0;
    }

    success(`Environment ${bold(envId)} resumed and active.`);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: destroy
// ---------------------------------------------------------------------------

async function destroyEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const rawEnvId = argv.find((a) => !a.startsWith('-'));

  const { values } = parseArgs({
    args: argv.filter((a) => a !== rawEnvId),
    options: {
      yes: { type: 'boolean', short: 'y', default: false },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false,
    strict: false
  });

  const envId = resolveEnvId(rawEnvId);
  if (!envId) {
    error('hebrah env destroy: environment_id required');
    console.error('Usage: hebrah env destroy <environment_id> [--yes]');
    return 1;
  }

  if (!values.yes && !values.json) {
    const rl = createInterface({ input, output });
    try {
      const answer = await rl.question(
        `Are you sure you want to destroy environment ${bold(envId)}? All attached DBs will be wiped. (y/N): `
      );
      if (!['y', 'yes'].includes(answer.trim().toLowerCase())) {
        warn('Destroy cancelled.');
        return 0;
      }
    } finally {
      rl.close();
    }
  }

  try {
    const result = await api.delete<{ ok: boolean; id: string; status: string }>(
      `/v1/environments/${safeId(envId, 'environment_id')}`
    );

    if (values.json) {
      json(result);
      return 0;
    }

    success(`Environment ${bold(envId)} destroyed.`);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: query
// ---------------------------------------------------------------------------

async function queryEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const firstPositional = argv.find((a) => !a.startsWith('-'));
  // If firstPositional looks like SQL (contains whitespace or starts with SELECT/WITH/SHOW/EXPLAIN),
  // treat it as the SQL query and resolve envId from defaultEnvId.
  const firstLooksLikeSql =
    typeof firstPositional === 'string' &&
    (/\s/.test(firstPositional.trim()) ||
      /^(select|with|show|explain|insert|update|delete)\b/i.test(firstPositional.trim()));

  const rawEnvId = firstLooksLikeSql ? undefined : firstPositional;
  const remaining = rawEnvId ? argv.filter((a) => a !== rawEnvId) : argv;

  // The first non-flag positional in remaining is the SQL query if not passed via --sql
  const { values, positionals } = parseArgs({
    args: remaining,
    options: {
      sql: { type: 'string' },
      addon: { type: 'string', default: 'postgres' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(rawEnvId);
  const sql = values.sql ?? positionals[0];

  if (!envId || !sql) {
    error('hebrah env query: environment_id and SQL query required');
    console.error('Usage: hebrah env query <environment_id> "<sql>" [--addon <postgres>] [--json]');
    return 1;
  }

  const addon = typeof values.addon === 'string' ? values.addon : 'postgres';

  try {
    const res = await api.post<DbQueryResult>(
      `/v1/environments/${safeId(envId, 'environment_id')}/db/query`,
      {
        sql,
        addon,
        actor_type: 'agent'
      }
    );

    if (values.json) {
      json(res);
      return 0;
    }

    if (res.rows && res.rows.length > 0) {
      const headers = Object.keys(res.rows[0]);
      const rows = res.rows.map((r) => headers.map((h) => String(r[h] ?? '')));
      table(headers, rows);
    } else {
      console.log(dim('(no rows returned)'));
    }

    console.log();
    console.log(
      dim(
        `${res.row_count} rows · ${formatBytes(res.bytes_egressed)} egressed · ${res.duration_ms}ms · credential-blind`
      )
    );
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: wireguard
// ---------------------------------------------------------------------------

async function wireguardEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const rawEnvId = argv.find((a) => !a.startsWith('-'));

  const { values } = parseArgs({
    args: argv.filter((a) => a !== rawEnvId),
    options: {
      out: { type: 'string' },
      'reveal-private-key': { type: 'boolean', default: false },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false,
    strict: false
  });

  const envId = resolveEnvId(rawEnvId);
  if (!envId) {
    error('hebrah env wireguard: environment_id required');
    console.error('Usage: hebrah env wireguard <environment_id> [--out <file.conf>] [--reveal-private-key] [--json]');
    return 1;
  }

  const revealKey = Boolean(values['reveal-private-key']);

  try {
    const wg = await api.get<WireguardConfigResult>(
      `/v1/environments/${safeId(envId, 'environment_id')}/wireguard/config`
    );

    const configText = normalizeWireguardConfig(
      wg.config_text || (wg as any).config || ''
    );
    const outPath = typeof values.out === 'string' ? values.out : undefined;

    if (outPath) {
      if (existsSync(outPath)) {
        const st = lstatSync(outPath);
        if (st.isSymbolicLink()) {
          throw new Error(`Security error: Refusing to write WireGuard private key to symlink (${outPath})`);
        }
      }
      writeFileSync(outPath, configText, { encoding: 'utf-8', mode: 0o600 });
      try {
        chmodSync(outPath, 0o600);
      } catch {
        // Ignore on platforms that don't support POSIX modes
      }
      if (values.json) {
        const safeConfig = revealKey ? configText : redactWireguardPrivateKey(configText);
        json({
          ...wg,
          ...(('config' in (wg as any)) ? { config: safeConfig } : {}),
          config_text: safeConfig,
          saved_to: outPath,
          mode: '0600'
        });
        return 0;
      }
      success(`WireGuard configuration written to ${bold(outPath)} (permissions 0600)`);
      console.log();
      info(`Import ${outPath} into WireGuard app or run: "wg-quick up ${outPath}"`);
      info(`Then connect DBeaver / TablePlus directly to ${wg.client_ip.replace('/32', '')}:5432`);
      return 0;
    }

    if (values.json) {
      const safeConfig = revealKey ? configText : redactWireguardPrivateKey(configText);
      json({
        ...wg,
        ...(('config' in (wg as any)) ? { config: safeConfig } : {}),
        config_text: safeConfig
      });
      return 0;
    }

    console.log(bold(`WireGuard Mesh Tunnel Config — ${envId}:`));
    console.log(dim('──────────────────────────────────────────────────────────────────'));
    console.log(revealKey ? configText : redactWireguardPrivateKey(configText));
    console.log(dim('──────────────────────────────────────────────────────────────────'));
    console.log();
    info('Save full configuration with private key using "--out ./hebrah.conf" (writes with 0600 permissions).');
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: scenario
// ---------------------------------------------------------------------------

async function scenarioEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const rawEnvId = argv.find((a) => !a.startsWith('-'));

  const { values } = parseArgs({
    args: argv.filter((a) => a !== rawEnvId),
    options: {
      type: { type: 'string' },
      scenario: { type: 'string' },
      'patient-id': { type: 'string' },
      patient: { type: 'string' },
      notes: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false,
    strict: false
  });

  const envId = resolveEnvId(rawEnvId);
  const scenarioType =
    typeof values.scenario === 'string'
      ? values.scenario
      : typeof values.type === 'string'
        ? values.type
        : '';
  const patientId =
    typeof values.patient === 'string'
      ? values.patient
      : typeof values['patient-id'] === 'string'
        ? values['patient-id']
        : undefined;
  const notes = typeof values.notes === 'string' ? values.notes : undefined;

  if (!envId || !scenarioType) {
    error('hebrah env scenario: environment_id and --type required');
    console.error(
      'Usage: hebrah env scenario <environment_id> --type <admit_patient|transfer_patient|discharge_patient|abnormal_lab_alert> [--patient-id <pid>] [--notes <notes>] [--json]'
    );
    return 1;
  }

  try {
    const res = await api.post<ClinicScenarioResult>(
      `/v1/environments/${safeId(envId, 'environment_id')}/clinic/scenarios`,
      {
        scenario: scenarioType,
        patient_id: patientId,
        notes
      }
    );

    if (values.json) {
      json(res);
      return 0;
    }

    success(`Clinical scenario triggered: ${bold(res.scenario)}`);
    console.log();
    const hl7Text = (res.hl7_message ?? (res as any).hl7_event ?? '') as string;
    kv([
      ['Scenario', res.scenario],
      ['WebSocket Broadcast', res.websocket_broadcast ? green('delivered to subscribers') : 'none'],
      ['Generated HL7 Event', dim(hl7Text.split('\r')[0] || res.scenario)]
    ]);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: db-proxy
// ---------------------------------------------------------------------------

async function dbProxyEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const nonFlags = argv.filter((a) => !a.startsWith('-'));
  const rawEnvId = nonFlags[0];
  const rawPositionalPort = nonFlags[1];

  const { values } = parseArgs({
    args: argv.filter((a) => a !== rawEnvId && a !== rawPositionalPort),
    options: {
      port: { type: 'string' },
      addon: { type: 'string', default: 'postgres' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(rawEnvId);
  if (!envId) {
    error('hebrah env db-proxy: environment_id required');
    console.error('Usage: hebrah env db-proxy <environment_id> [port] [--port 5432] [--addon postgres] [--json]');
    return 1;
  }

  try {
    const detail = await api.get<EnvironmentDetail>(`/v1/environments/${safeId(envId, 'environment_id')}`);

    const wgIp = detail.wireguard_ip ?? '10.42.0.1';
    const portStr = typeof values.port === 'string' ? values.port : (rawPositionalPort ?? '5432');
    const port = parseInt(portStr, 10) || 5432;
    const addon = typeof values.addon === 'string' ? values.addon : 'postgres';

    const infoData = {
      environment_id: detail.id,
      host: wgIp,
      local_proxy_host: '127.0.0.1',
      port,
      database: 'clinic_ehr',
      user: 'postgres',
      ssl_mode: 'prefer',
      addon,
      connection_string: `postgresql://postgres@${wgIp}:${port}/clinic_ehr`,
      local_proxy_command: `hebrah db proxy ${detail.id} ${port}`
    };

    if (values.json) {
      json(infoData);
      return 0;
    }

    console.log(bold(`Developer Database GUI Coordinates — ${detail.name} (${detail.id})`));
    console.log();
    kv([
      ['Host (Local Proxy)', `127.0.0.1 (via "hebrah db proxy ${detail.id} ${port}")`],
      ['Host (WireGuard)', wgIp],
      ['Port', String(port)],
      ['Database', 'clinic_ehr'],
      ['User', 'postgres'],
      ['Addon Module', addon],
      ['Connection URL', infoData.connection_string]
    ]);
    console.log();
    info('Instructions for DBeaver / TablePlus / DataGrip:');
    console.log(dim(`  Option A (Instant Local Tunnel): Run "hebrah db proxy ${detail.id} ${port}" and connect to 127.0.0.1:${port}`));
    console.log(dim(`  Option B (WireGuard Mesh): Run "hebrah db wireguard ${detail.id} --out ./hb-env.conf" and connect to ${wgIp}:${port}`));
    console.log(dim(`  AI Agents: Continue accessing data credential-blind via "hebrah db query ${detail.id} <sql>"`));

    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}
