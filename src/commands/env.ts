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
import { hostname, platform } from 'node:os';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { api, safeId, CLI_VERSION } from '../api/client.js';
import { updateCredentials } from '../config/credentials.js';
import {
  generateWireguardKeypair,
  normalizeWireguardConfig,
  redactWireguardPrivateKey,
  writeWireguardConfigFile,
  resolveStaticEnvId as resolveEnvId
} from '../util/wireguard.js';
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
  formatCents,
  sanitizeTerminalText,
  redactSecrets
} from '../output/format.js';
import { getArgv } from '../util/args.js';

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
  config?: string;
}

export interface ClinicScenarioResult {
  ok: boolean;
  scenario: string;
  hl7_message: string;
  hl7_event?: string;
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
    case 'info':
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
    case 'tables':
      return tablesEnv(subArgv, { ...options, _argv: subArgv });
    case 'patients':
      return patientsEnv(subArgv, { ...options, _argv: subArgv });
    case 'admit':
      return admitPatientsEnv(subArgv, { ...options, _argv: subArgv });
    case 'specialty-packs':
    case 'packs':
      return specialtyPacksEnv(subArgv, { ...options, _argv: subArgv });
    case 'ecg':
    case 'cardiology':
      return ecgEnv(subArgv, { ...options, _argv: subArgv });
    case 'cohorts':
    case 'branches':
      return cohortsEnv(subArgv, { ...options, _argv: subArgv });
    case 'cds-cascade':
    case 'cascade':
      return cdsCascadeEnv(subArgv, { ...options, _argv: subArgv });
    case 'x12-benchmark':
    case 'benchmark':
      return x12BenchmarkEnv(subArgv, { ...options, _argv: subArgv });
    case 'fhir':
      return fhirEnv(subArgv, { ...options, _argv: subArgv });
    case 'logs':
    case 'log':
      return logsEnv(subArgv, { ...options, _argv: subArgv });
    case 'studio':
    case 'chat':
      return studioEnv(subArgv, { ...options, _argv: subArgv });
    case 'open-data':
    case 'evidence':
      return openDataEnv(subArgv, { ...options, _argv: subArgv });
    case 'architect':
      return architectEnv(subArgv, { ...options, _argv: subArgv });
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
  architect "<prompt>"         Design or auto-provision via Conversational Architect
  connect (attach) <id>        Attach this agent to an environment & set default
  status (info, show) [id]     Show details, endpoints, and connected agents
  studio (chat) [id] "<msg>"   Consult the isolated Per-Environment GCP AI Studio
  open-data (evidence) [id]    Inspect or search Open-Data Clinical & DICOM packs
  tables [id]                  List isolated database tables and row counts
  patients [id]                List synthetic patients with clinical filters
  admit [id] --count <n>       Dynamically admit synthetic patients (up to 500, specialty packs, depth=rich)
  specialty-packs [id]         List or inspect the 12 clinical specialty condition packs
  ecg [action] [id]            Manage PTB-XL 12-lead 100 Hz ECGs (exemplars, list, waveform, attach, compare)
  cohorts [action] [id]        Manage research cohort branches (list, create, fork, compare)
  cds-cascade [id]             Evaluate HL7 CDS Hooks 2.0 order-sign prescribing cascade detection
  x12-benchmark [id]           Benchmark environment X12 837/835 claims against CMS Medicare utilization
  fhir [id] <ResourceType>     Query environment-scoped FHIR R4 bundles (Patient, MedicationRequest, Observation, etc.)
  logs [id]                    View environment activity and audit logs
  pause [id]                   Pause environment (halts hourly resource charge)
  resume [id]                  Resume a paused environment
  destroy (rm) <id>            Tear down an environment
  query (sql) [id] "<sql>"     Run credential-blind query on attached DB
  wireguard (wg) [id]          Export WireGuard VPN config for GUI access
  scenario (trigger) [id]      Trigger a clinical EHR event (HL7 / FHIR)
  db-proxy [id]                Show developer GUI connection coordinates

Flags (global for subcommands):
  --json                       Emit JSON machine-readable output

Examples:
  hebrah env list
  hebrah env connect 4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94 --name "clinic-agent"
  hebrah env create --name "Pediatric Pilot" --clinic pediatrics_neonatal --addons postgres,neo4j
  hebrah env architect "Design an ICU sepsis environment with Qdrant and Neo4j" --auto-provision
  hebrah env studio "Join our patients with PubMed RCT evidence and show CDS Hooks cards"
  hebrah env open-data --search "sepsis"
  hebrah env query "SELECT * FROM patients LIMIT 5"
  hebrah env wireguard --out ./hebrah-clinic.conf
  hebrah env scenario --type admit_patient --patient-id P-1002
  hebrah env logs --limit 20
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
  if (!Number.isInteger(patientCount) || patientCount < 1 || patientCount > 5000) {
    error('hebrah env create: --patients must be an integer between 1 and 5000');
    return 1;
  }
  if (!Number.isInteger(bedCount) || bedCount < 1 || bedCount > 5000) {
    error('hebrah env create: --beds must be an integer between 1 and 5000');
    return 1;
  }

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
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      name: { type: 'string' },
      'agent-name': { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env connect: environment_id required');
    error('Usage: hebrah env connect <environment_id> [--agent-name <name>] [--json]');
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
        cli_version: CLI_VERSION,
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
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env status: environment_id required');
    error('Usage: hebrah env status <environment_id> [--json]');
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

    console.log(bold(`Environment: ${sanitizeTerminalText(String(detail.name ?? ''))}`));
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
        console.log(
          `  • ${bold(sanitizeTerminalText(String(db.type ?? '')))}: ${green(sanitizeTerminalText(String(db.status ?? '')))} · Port ${sanitizeTerminalText(String(db.port ?? ''))} · ${sanitizeTerminalText(String(db.size_mb ?? ''))} MB (${sanitizeTerminalText(String(db.tables_count ?? ''))} tables)`
        );
      }
    }

    if (detail.connected_agents && detail.connected_agents.length > 0) {
      console.log();
      console.log(bold('Active AI Agents:'));
      for (const ag of detail.connected_agents) {
        console.log(
          `  • ${cyan(sanitizeTerminalText(String(ag.name ?? '')))} (${sanitizeTerminalText(String(ag.agent_id ?? ''))}) connected at ${sanitizeTerminalText(String(ag.connected_at ?? ''))}`
        );
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
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env pause: environment_id required');
    error('Usage: hebrah env pause <environment_id>');
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
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env resume: environment_id required');
    error('Usage: hebrah env resume <environment_id>');
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
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      yes: { type: 'boolean', short: 'y', default: false },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env destroy: environment_id required');
    error('Usage: hebrah env destroy <environment_id> [--yes]');
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
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      sql: { type: 'string' },
      addon: { type: 'string', default: 'postgres' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const firstPositional = positionals[0];
  // If firstPositional looks like SQL (contains whitespace or starts with SELECT/WITH/SHOW/EXPLAIN),
  // treat it as the SQL query and resolve envId from defaultEnvId.
  const firstLooksLikeSql =
    typeof firstPositional === 'string' &&
    (/\s/.test(firstPositional.trim()) ||
      /^(select|with|show|explain|insert|update|delete|pragma|match)\b/i.test(firstPositional.trim()));

  const rawEnvId = firstLooksLikeSql ? undefined : firstPositional;
  const positionalSql = firstLooksLikeSql ? firstPositional : positionals[1];

  const envId = resolveEnvId(rawEnvId);
  const sql = typeof values.sql === 'string' ? values.sql : positionalSql;

  if (!envId || !sql) {
    error('hebrah env query: environment_id and SQL query required');
    error('Usage: hebrah env query <environment_id> "<sql>" [--addon <postgres>] [--json]');
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
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      out: { type: 'string' },
      'reveal-private-key': { type: 'boolean', default: false },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env wireguard: environment_id required');
    error('Usage: hebrah env wireguard <environment_id> [--out <file.conf>] [--reveal-private-key] [--json]');
    return 1;
  }

  const revealKey = Boolean(values['reveal-private-key']);

  try {
    let wg = await api.get<WireguardConfigResult>(
      `/v1/environments/${safeId(envId, 'environment_id')}/wireguard/config`
    );

    let clientPrivKey: string | undefined;
    const rawCfg = wg.config_text || wg.config || '';
    if (rawCfg.includes('<GENERATE_CLIENT_PRIVATE_KEY')) {
      const kp = generateWireguardKeypair();
      clientPrivKey = kp.privateKey;
      try {
        const peerRes = await api.post<WireguardConfigResult>(
          `/v1/environments/${safeId(envId, 'environment_id')}/vpn/peers`,
          {
            client_name: 'cli-developer-workstation',
            public_key: kp.publicKey
          }
        );
        if (peerRes && (peerRes.config_text || peerRes.config)) {
          wg = { ...wg, ...peerRes };
        }
      } catch {
        // Fallback to local key substitution if peer registration endpoint is not mocked in tests
      }
    }

    const configText = normalizeWireguardConfig(
      wg.config_text || wg.config || '',
      clientPrivKey
    );
    const outPath = typeof values.out === 'string' ? values.out : undefined;

    if (outPath) {
      writeWireguardConfigFile(outPath, configText);
      if (values.json) {
        const safeConfig = revealKey ? configText : redactWireguardPrivateKey(configText);
        json({
          ...wg,
          ...('config' in wg ? { config: safeConfig } : {}),
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
        ...('config' in wg ? { config: safeConfig } : {}),
        config_text: safeConfig
      });
      return 0;
    }

    console.log(bold(`WireGuard Mesh Tunnel Config — ${sanitizeTerminalText(envId)}:`));
    console.log(dim('──────────────────────────────────────────────────────────────────'));
    console.log(
      sanitizeTerminalText(
        revealKey ? configText : redactWireguardPrivateKey(configText)
      )
    );
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
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      type: { type: 'string' },
      scenario: { type: 'string' },
      'patient-id': { type: 'string' },
      patient: { type: 'string' },
      notes: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
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
    error(
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
    const hl7Text = res.hl7_message ?? res.hl7_event ?? '';
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
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      port: { type: 'string' },
      addon: { type: 'string', default: 'postgres' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  let rawEnvId: string | undefined = positionals[0];
  let rawPositionalPort: string | undefined = positionals[1];
  if (rawEnvId && /^\d{2,5}$/.test(rawEnvId) && !rawPositionalPort) {
    rawPositionalPort = rawEnvId;
    rawEnvId = undefined;
  }

  const envId = resolveEnvId(rawEnvId);
  if (!envId) {
    error('hebrah env db-proxy: environment_id required');
    error('Usage: hebrah env db-proxy <environment_id> [port] [--port 5432] [--addon postgres] [--json]');
    return 1;
  }

  const portStr = typeof values.port === 'string' ? values.port : (rawPositionalPort ?? '5432');
  const port = parseInt(portStr, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    error('hebrah env db-proxy: port must be between 1 and 65535');
    return 1;
  }

  try {
    const detail = await api.get<EnvironmentDetail>(`/v1/environments/${safeId(envId, 'environment_id')}`);

    const wgIp = detail.wireguard_ip ?? '10.42.0.1';
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

    console.log(
      bold(
        `Developer Database GUI Coordinates — ${sanitizeTerminalText(String(detail.name ?? ''))} (${sanitizeTerminalText(String(detail.id ?? ''))})`
      )
    );
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

// ---------------------------------------------------------------------------
// Subcommand: tables
// ---------------------------------------------------------------------------

async function tablesEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env tables: environment_id required');
    error('Usage: hebrah env tables [environment_id] [--json]');
    return 1;
  }

  try {
    const res = await api.get<{
      environment_id: string;
      schema: string;
      table_count: number;
      total_rows: number;
      tables: Array<{
        name: string;
        table_name: string;
        row_count: number;
        column_count: number;
        category: string;
        description: string;
      }>;
    }>(`/v1/environments/${safeId(envId, 'environment_id')}/db/tables`);

    if (values.json) {
      json(res);
      return 0;
    }

    console.log(
      bold(
        `Isolated Database Schema — ${sanitizeTerminalText(String(res.schema ?? ''))} (${sanitizeTerminalText(String(res.environment_id ?? ''))})`
      )
    );
    console.log();
    const tablesList = res.tables ?? [];
    if (tablesList.length === 0) {
      console.log(dim('No tables found in schema.'));
      return 0;
    }

    const headers = ['TABLE', 'CATEGORY', 'ROWS', 'COLUMNS', 'DESCRIPTION'];
    const rows = tablesList.map((t) => [
      t.name ?? t.table_name,
      t.category ?? 'clinical',
      String(t.row_count ?? 0),
      String(t.column_count ?? 0),
      (t.description ?? '').slice(0, 56)
    ]);
    table(headers, rows);
    console.log();
    console.log(dim(`${res.table_count ?? tablesList.length} tables · ${res.total_rows ?? 0} total rows`));
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: patients
// ---------------------------------------------------------------------------

async function patientsEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      department: { type: 'string' },
      diagnosis: { type: 'string' },
      acuity: { type: 'string' },
      search: { type: 'string' },
      limit: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env patients: environment_id required');
    error(
      'Usage: hebrah env patients [environment_id] [--department <dept>] [--diagnosis <dx>] [--acuity <acuity>] [--search <q>] [--limit <n>] [--json]'
    );
    return 1;
  }

  const queryParams: Record<string, string> = {};
  if (typeof values.department === 'string' && values.department.trim()) {
    queryParams.department = values.department.trim();
  }
  if (typeof values.diagnosis === 'string' && values.diagnosis.trim()) {
    queryParams.diagnosis = values.diagnosis.trim();
  }
  if (typeof values.acuity === 'string' && values.acuity.trim()) {
    queryParams.acuity = values.acuity.trim();
  }
  if (typeof values.search === 'string' && values.search.trim()) {
    queryParams.search = values.search.trim();
  }
  if (typeof values.limit === 'string' && values.limit.trim()) {
    queryParams.limit = values.limit.trim();
  }

  try {
    const res = await api.get<Array<Record<string, unknown>>>(
      `/v1/environments/${safeId(envId, 'environment_id')}/ehr/patients`,
      queryParams
    );
    const patientsList = Array.isArray(res) ? res : [];

    if (values.json) {
      json(patientsList);
      return 0;
    }

    if (patientsList.length === 0) {
      console.log(dim('No matching synthetic patients found.'));
      return 0;
    }

    const headers = ['ID', 'MRN', 'PATIENT NAME', 'DEPT', 'ACUITY', 'PRIMARY CONDITION'];
    const rows = patientsList.map((p) => [
      String(p.id ?? ''),
      String(p.mrn ?? ''),
      `${p.first_name ?? ''} ${p.last_name ?? ''}`.trim(),
      String(p.department ?? ''),
      String(p.acuity_level ?? p.acuity ?? ''),
      String(p.primary_condition ?? '').slice(0, 48)
    ]);
    table(headers, rows);
    console.log();
    console.log(dim(`Showing ${patientsList.length} synthetic patient(s)`));
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: admit
// ---------------------------------------------------------------------------

async function admitPatientsEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      count: { type: 'string', default: '10' },
      department: { type: 'string' },
      departments: { type: 'string' },
      diagnosis: { type: 'string' },
      acuity: { type: 'string' },
      'specialty-pack': { type: 'string' },
      pack: { type: 'string' },
      conditions: { type: 'string' },
      depth: { type: 'string' },
      'branch-id': { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env admit: environment_id required');
    error(
      'Usage: hebrah env admit [environment_id] [--count 10] [--specialty-pack <id>] [--conditions <ids>] [--depth standard|rich] [--branch-id <id>] [--department <dept>] [--diagnosis <dx>] [--acuity <acuity>] [--json]'
    );
    return 1;
  }

  const count = parseInt(String(values.count ?? '10'), 10);
  if (!Number.isInteger(count) || count < 1 || count > 500) {
    error('hebrah env admit: --count must be an integer between 1 and 500');
    return 1;
  }
  const body: Record<string, unknown> = { count };
  const rawDepts =
    typeof values.departments === 'string'
      ? values.departments
      : typeof values.department === 'string'
        ? values.department
        : '';
  if (rawDepts) {
    body.departments = rawDepts.split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (typeof values.diagnosis === 'string' && values.diagnosis.trim()) {
    body.diagnosis_pathways = values.diagnosis.split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (typeof values.acuity === 'string' && values.acuity.trim()) {
    body.acuity_levels = values.acuity.split(',').map((s) => s.trim()).filter(Boolean);
  }
  const specialtyPack =
    typeof values['specialty-pack'] === 'string'
      ? values['specialty-pack'].trim()
      : typeof values.pack === 'string'
        ? values.pack.trim()
        : '';
  if (specialtyPack) {
    body.specialty_pack_id = specialtyPack;
  }
  if (typeof values.conditions === 'string' && values.conditions.trim()) {
    body.condition_ids = values.conditions.split(',').map((s) => s.trim()).filter(Boolean);
  }
  if (typeof values.depth === 'string' && values.depth.trim()) {
    body.depth = values.depth.trim();
  }
  if (typeof values['branch-id'] === 'string' && values['branch-id'].trim()) {
    body.branch_id = values['branch-id'].trim();
  }

  try {
    const res = await api.post<Record<string, unknown>>(
      `/v1/environments/${safeId(envId, 'environment_id')}/ehr/patients/generate`,
      body
    );

    if (values.json) {
      json(res);
      return 0;
    }

    const admittedCount = Number(res.admitted_count ?? count);
    const packSuffix = specialtyPack ? ` (pack: ${bold(specialtyPack)}${body.depth ? `, depth: ${body.depth}` : ''})` : '';
    success(`Admitted ${bold(String(admittedCount))} synthetic patients into environment ${bold(envId)}${packSuffix}`);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: logs
// ---------------------------------------------------------------------------

async function logsEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      limit: { type: 'string', default: '25' },
      'event-type': { type: 'string' },
      'actor-type': { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env logs: environment_id required');
    error('Usage: hebrah env logs [environment_id] [--limit 25] [--event-type <type>] [--json]');
    return 1;
  }

  const queryParams: Record<string, string> = {
    limit: typeof values.limit === 'string' ? values.limit : '25'
  };
  if (typeof values['event-type'] === 'string' && values['event-type'].trim()) {
    queryParams.event_type = values['event-type'].trim();
  }
  if (typeof values['actor-type'] === 'string' && values['actor-type'].trim()) {
    queryParams.actor_type = values['actor-type'].trim();
  }

  try {
    const res = await api.get<Array<Record<string, unknown>>>(
      `/v1/environments/${safeId(envId, 'environment_id')}/logs`,
      queryParams
    );
    const logsList = Array.isArray(res) ? res : [];

    if (values.json) {
      json(logsList);
      return 0;
    }

    if (logsList.length === 0) {
      console.log(dim('No activity logs found for this environment.'));
      return 0;
    }

    const headers = ['TIMESTAMP', 'EVENT', 'ACTOR', 'STATUS', 'SUMMARY'];
    const rows = logsList.map((l) => [
      String(l.created_at ?? '').slice(0, 19),
      String(l.event_type ?? ''),
      `${l.actor_type ?? 'agent'}:${l.actor_id ?? ''}`.slice(0, 24),
      l.status === 'success' ? green('success') : yellow(String(l.status ?? 'ok')),
      String(l.summary ?? '').slice(0, 56)
    ]);
    table(headers, rows);
    console.log();
    console.log(dim(`Showing ${logsList.length} activity event(s) for ${envId}`));
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: studio
// ---------------------------------------------------------------------------

async function studioEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      prompt: { type: 'string' },
      message: { type: 'string' },
      'session-id': { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const firstPositional = positionals[0];
  // If firstPositional looks like a natural-language prompt (contains whitespace),
  // resolve envId from defaultEnvId and treat firstPositional as the message.
  const firstLooksLikePrompt =
    typeof firstPositional === 'string' && /\s/.test(firstPositional.trim());

  const rawEnvId = firstLooksLikePrompt ? undefined : firstPositional;
  const positionalPrompt = firstLooksLikePrompt ? firstPositional : positionals[1];

  const envId = resolveEnvId(rawEnvId);
  const message =
    typeof values.prompt === 'string'
      ? values.prompt
      : typeof values.message === 'string'
        ? values.message
        : positionalPrompt;

  if (!envId || !message) {
    error('hebrah env studio: environment_id and prompt message required');
    error(
      'Usage: hebrah env studio [environment_id] "<prompt>" [--session-id <id>] [--json]'
    );
    return 1;
  }

  const body: Record<string, unknown> = {
    message,
    auto_run_tools: true
  };
  if (typeof values['session-id'] === 'string' && values['session-id'].trim()) {
    body.session_id = values['session-id'].trim();
  }

  try {
    const res = await api.post<Record<string, unknown>>(
      `/v1/environments/${safeId(envId, 'environment_id')}/studio/chat`,
      body
    );

    if (values.json) {
      json(res);
      return 0;
    }

    const reply = redactSecrets(sanitizeTerminalText(String(res.reply ?? res.assistant_reply ?? '')));
    const toolsInvoked = Array.isArray(res.tools_invoked) ? (res.tools_invoked as string[]) : [];
    const packsQueried = Array.isArray(res.open_data_packs_queried)
      ? (res.open_data_packs_queried as string[])
      : [];
    const guardrail = res.guardrail_triggered ? String(res.guardrail_triggered) : null;

    console.log(bold(`Environment AI Studio — ${sanitizeTerminalText(envId)}`));
    console.log(dim('──────────────────────────────────────────────────────────────────'));
    console.log(reply);
    console.log(dim('──────────────────────────────────────────────────────────────────'));
    kv([
      ['Session ID', String(res.session_id ?? 'n/a')],
      ['Schema', String(res.schema_name ?? 'isolated')],
      ['Tools Executed', toolsInvoked.join(', ') || 'none'],
      ['Open-Data Packs', packsQueried.join(', ') || 'clinical_knowledge_v1'],
      ['Guardrail Status', guardrail ? yellow(`blocked (${guardrail})`) : green('in_scope (3-layer skill lock active)')]
    ]);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: open-data
// ---------------------------------------------------------------------------

async function openDataEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      search: { type: 'string' },
      query: { type: 'string' },
      subpack: { type: 'string' },
      specialty: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env open-data: environment_id required');
    error(
      'Usage: hebrah env open-data [environment_id] [--search <term>] [--subpack <id>] [--specialty <spec>] [--json]'
    );
    return 1;
  }

  const queryParams: Record<string, string> = {};
  const searchVal =
    typeof values.search === 'string'
      ? values.search
      : typeof values.query === 'string'
        ? values.query
        : '';
  if (searchVal.trim()) queryParams.search = searchVal.trim();
  if (typeof values.subpack === 'string' && values.subpack.trim()) {
    queryParams.subpack = values.subpack.trim();
  }
  if (typeof values.specialty === 'string' && values.specialty.trim()) {
    queryParams.specialty = values.specialty.trim();
  }

  try {
    const res = await api.get<Record<string, unknown>>(
      `/v1/environments/${safeId(envId, 'environment_id')}/open-data/catalog`,
      queryParams
    );

    if (values.json) {
      json(res);
      return 0;
    }

    const ck = (res.clinical_knowledge_pack ?? {}) as Record<string, unknown>;
    const dicom = (res.dicom_imaging_pack ?? {}) as Record<string, unknown>;
    const records = Array.isArray(ck.records) ? (ck.records as Array<Record<string, unknown>>) : [];

    console.log(
      bold(
        `Open-Data Clinical & Imaging Enrichment Catalog — ${sanitizeTerminalText(String(res.environment_name ?? envId))}`
      )
    );
    console.log();
    kv([
      ['Environment ID', String(res.environment_id ?? envId)],
      ['Isolated Schema', String(res.schema_name ?? 'n/a')],
      ['Clinical Knowledge Pack', `clinical_knowledge_v1 (${ck.total ?? records.length} records)`],
      ['DICOM Imaging Pack', `dicom_imaging_v1 (${dicom.total_exemplars ?? 0} studies)`]
    ]);

    if (records.length > 0) {
      console.log();
      const headers = ['ID', 'SUB-PACK', 'SPECIALTY', 'LICENSE', 'TITLE'];
      const rows = records.slice(0, 15).map((r) => [
        String(r.id ?? ''),
        String(r.subpack ?? ''),
        String(r.specialty ?? ''),
        String(r.license ?? ''),
        String(r.title ?? '').slice(0, 48)
      ]);
      table(headers, rows);
    }
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: architect
// ---------------------------------------------------------------------------

async function architectEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      prompt: { type: 'string' },
      message: { type: 'string' },
      'session-id': { type: 'string' },
      'auto-provision': { type: 'boolean', default: false },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const message =
    typeof values.prompt === 'string'
      ? values.prompt
      : typeof values.message === 'string'
        ? values.message
        : positionals[0];

  if (!message || !message.trim()) {
    error('hebrah env architect: prompt message required');
    error(
      'Usage: hebrah env architect "<prompt>" [--auto-provision] [--session-id <id>] [--json]'
    );
    return 1;
  }

  const body: Record<string, unknown> = {
    message: message.trim(),
    auto_provision: Boolean(values['auto-provision'])
  };
  if (typeof values['session-id'] === 'string' && values['session-id'].trim()) {
    body.session_id = values['session-id'].trim();
  }

  try {
    const res = await api.post<Record<string, unknown>>('/v1/environments/architect/chat', body);

    const provisioned = res.provisioned_environment as Record<string, unknown> | undefined;
    if (provisioned?.id && typeof provisioned.id === 'string') {
      try {
        updateCredentials({ defaultEnvId: provisioned.id });
      } catch {
        // Ignore if credentials file not initialized
      }
    }

    if (values.json) {
      json(res);
      return 0;
    }

    const reply = redactSecrets(sanitizeTerminalText(String(res.assistant_reply ?? res.reply ?? '')));
    const bp = (res.blueprint ?? {}) as Record<string, unknown>;

    console.log(bold('Conversational Environment Architect'));
    console.log(dim('──────────────────────────────────────────────────────────────────'));
    console.log(reply);
    console.log(dim('──────────────────────────────────────────────────────────────────'));
    kv([
      ['Session ID', String(res.session_id ?? 'n/a')],
      ['Scope Classification', String(res.scope_status ?? 'in_scope')],
      ['Blueprint Name', String(bp.name ?? 'Custom Clinical Environment')],
      ['Archetype', String(bp.clinic_type ?? 'hospital')],
      ['Database Modules', Array.isArray(bp.addons) ? bp.addons.join(', ') : 'postgres']
    ]);

    if (provisioned?.id) {
      console.log();
      success(`Auto-provisioned environment: ${bold(sanitizeTerminalText(String(provisioned.name ?? '')))} (${sanitizeTerminalText(String(provisioned.id))})`);
    }
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: specialty-packs
// ---------------------------------------------------------------------------

async function specialtyPacksEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      pack: { type: 'string' },
      id: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env specialty-packs: environment_id required');
    error('Usage: hebrah env specialty-packs [environment_id] [--pack <specialty_id>] [--json]');
    return 1;
  }

  const packId =
    typeof values.pack === 'string'
      ? values.pack.trim()
      : typeof values.id === 'string'
        ? values.id.trim()
        : positionals[1] ?? '';

  try {
    if (packId) {
      const res = await api.get<Record<string, unknown>>(
        `/v1/environments/${safeId(envId, 'environment_id')}/specialty-packs/${safeId(packId, 'specialty_id')}`
      );
      if (values.json) {
        json(res);
        return 0;
      }
      const conditions = Array.isArray(res.conditions)
        ? (res.conditions as Array<Record<string, unknown>>)
        : [];
      console.log(bold(`Specialty Pack: ${sanitizeTerminalText(String(res.name ?? packId))} (${packId})`));
      if (res.description) {
        console.log(dim(sanitizeTerminalText(String(res.description))));
      }
      console.log();
      const headers = ['CONDITION ID', 'LABEL', 'ICD-10', 'DEFAULT ACUITY'];
      const rows = conditions.map((c) => [
        String(c.id ?? ''),
        String(c.name ?? c.label ?? '').slice(0, 44),
        String(c.primary_icd10 ?? c.icd10 ?? ''),
        String(c.default_acuity ?? 'routine')
      ]);
      table(headers, rows);
      return 0;
    }

    const res = await api.get<Record<string, unknown>>(
      `/v1/environments/${safeId(envId, 'environment_id')}/specialty-packs`
    );
    if (values.json) {
      json(res);
      return 0;
    }
    const packs = Array.isArray(res.packs) ? (res.packs as Array<Record<string, unknown>>) : [];
    console.log(bold(`Specialty Condition Packs (${packs.length}) — Environment ${sanitizeTerminalText(envId)}`));
    console.log();
    const headers = ['PACK ID', 'NAME', 'CONDITIONS', 'SUMMARY'];
    const rows = packs.map((p) => [
      String(p.id ?? p.specialty_id ?? ''),
      String(p.name ?? p.label ?? ''),
      String(p.condition_count ?? (Array.isArray(p.conditions) ? p.conditions.length : 0)),
      String(p.description ?? '').slice(0, 52)
    ]);
    table(headers, rows);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: ecg (Cardiology ptbxl_ecg_v1)
// ---------------------------------------------------------------------------

async function ecgEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      superclass: { type: 'string' },
      patient: { type: 'string' },
      'patient-id': { type: 'string' },
      ecg: { type: 'string' },
      'ecg-id': { type: 'string' },
      study: { type: 'string' },
      left: { type: 'string' },
      right: { type: 'string' },
      notes: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const action = positionals[0] && ['exemplars', 'list', 'show', 'waveform', 'attach', 'compare'].includes(positionals[0])
    ? positionals[0]
    : 'list';
  const rawEnvArg = positionals[0] === action ? positionals[1] : positionals[0];
  const envId = resolveEnvId(rawEnvArg);
  if (!envId) {
    error('hebrah env ecg: environment_id required');
    error(
      'Usage: hebrah env ecg [exemplars|list|show|waveform|attach|compare] [environment_id] [--superclass NORM|MI|STTC|CD|HYP] [--patient <id>] [--ecg <id>] [--left <id> --right <id>] [--json]'
    );
    return 1;
  }

  const safeEnv = safeId(envId, 'environment_id');

  try {
    if (action === 'exemplars') {
      const q: Record<string, string> = {};
      if (typeof values.superclass === 'string' && values.superclass.trim()) {
        q.superclass = values.superclass.trim().toUpperCase();
      }
      const res = await api.get<Record<string, unknown>>(
        `/v1/environments/${safeEnv}/ecg/exemplars`,
        q
      );
      if (values.json) {
        json(res);
        return 0;
      }
      const exemplars = Array.isArray(res.exemplars)
        ? (res.exemplars as Array<Record<string, unknown>>)
        : [];
      console.log(bold(`PTB-XL 12-Lead ECG Exemplars (${exemplars.length}) — Environment ${sanitizeTerminalText(envId)}`));
      const headers = ['ECG ID', 'SUPERCLASS', 'AGE/SEX', 'HR (BPM)', 'AXIS', 'REPORT'];
      const rows = exemplars.map((e) => [
        String(e.ecg_id ?? ''),
        String(e.diagnostic_superclass ?? e.superclass ?? ''),
        `${e.age ?? '?'} / ${e.sex ?? '?'}`,
        String(e.heart_rate_bpm ?? ''),
        String(e.heart_axis ?? ''),
        String(e.report_en ?? e.report ?? '').slice(0, 46)
      ]);
      table(headers, rows);
      return 0;
    }

    if (action === 'attach') {
      const patientId =
        typeof values.patient === 'string'
          ? values.patient.trim()
          : typeof values['patient-id'] === 'string'
            ? values['patient-id'].trim()
            : '';
      if (!patientId) {
        error('hebrah env ecg attach: --patient <patient_id> is required');
        return 1;
      }
      const ecgIdRaw =
        typeof values.ecg === 'string'
          ? values.ecg.trim()
          : typeof values['ecg-id'] === 'string'
            ? values['ecg-id'].trim()
            : '';
      const body: Record<string, unknown> = { patient_id: patientId };
      if (ecgIdRaw) {
        body.ecg_id = /^\d+$/.test(ecgIdRaw) ? parseInt(ecgIdRaw, 10) : ecgIdRaw;
      }
      if (typeof values.superclass === 'string' && values.superclass.trim()) {
        body.superclass = values.superclass.trim().toUpperCase();
      }
      if (typeof values.notes === 'string' && values.notes.trim()) {
        body.clinical_notes = values.notes.trim();
      }
      const res = await api.post<Record<string, unknown>>(
        `/v1/environments/${safeEnv}/ecg/studies`,
        body
      );
      if (values.json) {
        json(res);
        return 0;
      }
      const study = (res.study ?? {}) as Record<string, unknown>;
      success(
        `Attached PTB-XL ECG #${study.ecg_id ?? ''} (${study.superclass ?? 'ECG'}) as study ${bold(String(study.id ?? ''))} to patient ${bold(patientId)}`
      );
      return 0;
    }

    if (action === 'compare') {
      const leftId = typeof values.left === 'string' ? values.left.trim() : '';
      const rightId = typeof values.right === 'string' ? values.right.trim() : '';
      if (!leftId || !rightId) {
        error('hebrah env ecg compare: --left <id> and --right <id> are required');
        return 1;
      }
      const res = await api.post<Record<string, unknown>>(
        `/v1/environments/${safeEnv}/ecg/compare`,
        {
          left_ecg_id: /^\d+$/.test(leftId) ? parseInt(leftId, 10) : leftId,
          right_ecg_id: /^\d+$/.test(rightId) ? parseInt(rightId, 10) : rightId
        }
      );
      if (values.json) {
        json(res);
        return 0;
      }
      console.log(bold(`12-Lead ECG Comparison: ${leftId} vs. ${rightId}`));
      kv([
        ['Left Superclass', String((res.left as Record<string, unknown>)?.diagnostic_superclass ?? '')],
        ['Right Superclass', String((res.right as Record<string, unknown>)?.diagnostic_superclass ?? '')],
        ['Summary', String(res.clinical_summary ?? res.summary ?? '12-lead delta computed')]
      ]);
      return 0;
    }

    if (action === 'show' || action === 'waveform') {
      const studyId =
        typeof values.study === 'string'
          ? values.study.trim()
          : typeof values.ecg === 'string'
            ? values.ecg.trim()
            : positionals[2] ?? positionals[1] ?? '';
      if (!studyId) {
        error(`hebrah env ecg ${action}: --study <study_or_ecg_id> is required`);
        return 1;
      }
      const suffix = action === 'waveform' ? '/waveform' : '';
      const res = await api.get<Record<string, unknown>>(
        `/v1/environments/${safeEnv}/ecg/studies/${safeId(studyId, 'study_id')}${suffix}`
      );
      if (values.json) {
        json(res);
        return 0;
      }
      kv([
        ['Study / ECG ID', String(res.id ?? res.ecg_id ?? studyId)],
        ['Patient ID', String(res.patient_id ?? 'exemplar')],
        ['Superclass', String(res.superclass ?? res.diagnostic_superclass ?? '')],
        ['Sampling Rate', `${res.sampling_rate_hz ?? 100} Hz`],
        ['Leads', Array.isArray(res.lead_names) ? res.lead_names.join(', ') : 'I, II, III, aVR, aVL, aVF, V1-V6']
      ]);
      return 0;
    }

    // Default: list studies in environment
    const q: Record<string, string> = {};
    const patFilter =
      typeof values.patient === 'string'
        ? values.patient.trim()
        : typeof values['patient-id'] === 'string'
          ? values['patient-id'].trim()
          : '';
    if (patFilter) q.patient_id = patFilter;
    if (typeof values.superclass === 'string' && values.superclass.trim()) {
      q.superclass = values.superclass.trim().toUpperCase();
    }
    const res = await api.get<Record<string, unknown>>(
      `/v1/environments/${safeEnv}/ecg/studies`,
      q
    );
    if (values.json) {
      json(res);
      return 0;
    }
    const studies = Array.isArray(res.studies) ? (res.studies as Array<Record<string, unknown>>) : [];
    console.log(bold(`Environment 12-Lead ECG Studies (${studies.length}) — ${sanitizeTerminalText(envId)}`));
    const headers = ['STUDY ID', 'PATIENT', 'PTB-XL ID', 'SUPERCLASS', 'HR (BPM)', 'INTERPRETATION'];
    const rows = studies.map((s) => [
      String(s.id ?? ''),
      String(s.patient_id ?? ''),
      String(s.ecg_id ?? ''),
      String(s.superclass ?? ''),
      String(s.heart_rate_bpm ?? ''),
      String(s.interpretation ?? s.report_en ?? '').slice(0, 44)
    ]);
    table(headers, rows);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: cohorts (Research Cohort Branches)
// ---------------------------------------------------------------------------

async function cohortsEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      name: { type: 'string' },
      pack: { type: 'string' },
      'specialty-pack': { type: 'string' },
      conditions: { type: 'string' },
      count: { type: 'string' },
      depth: { type: 'string' },
      branch: { type: 'string' },
      left: { type: 'string' },
      right: { type: 'string' },
      notes: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const action = positionals[0] && ['list', 'create', 'fork', 'compare'].includes(positionals[0])
    ? positionals[0]
    : 'list';
  const rawEnvArg = positionals[0] === action ? positionals[1] : positionals[0];
  const envId = resolveEnvId(rawEnvArg);
  if (!envId) {
    error('hebrah env cohorts: environment_id required');
    error(
      'Usage: hebrah env cohorts [list|create|fork|compare] [environment_id] [--name <name>] [--pack <id>] [--count <n>] [--depth standard|rich] [--left <id> --right <id>] [--json]'
    );
    return 1;
  }
  const safeEnv = safeId(envId, 'environment_id');

  try {
    if (action === 'create') {
      const name = typeof values.name === 'string' ? values.name.trim() : '';
      if (!name) {
        error('hebrah env cohorts create: --name <branch_name> is required');
        return 1;
      }
      const pack =
        typeof values['specialty-pack'] === 'string'
          ? values['specialty-pack'].trim()
          : typeof values.pack === 'string'
            ? values.pack.trim()
            : 'cardiology';
      const body: Record<string, unknown> = {
        name,
        specialty_pack_id: pack,
        count: values.count ? parseInt(String(values.count), 10) : 10,
        depth: typeof values.depth === 'string' ? values.depth.trim() : 'standard'
      };
      if (typeof values.conditions === 'string' && values.conditions.trim()) {
        body.condition_ids = values.conditions.split(',').map((s) => s.trim()).filter(Boolean);
      }
      if (typeof values.notes === 'string' && values.notes.trim()) {
        body.notes = values.notes.trim();
      }
      const res = await api.post<Record<string, unknown>>(
        `/v1/environments/${safeEnv}/cohorts/branches`,
        body
      );
      if (values.json) {
        json(res);
        return 0;
      }
      const br = (res.branch ?? {}) as Record<string, unknown>;
      success(`Created cohort branch ${bold(String(br.name ?? name))} (${br.id ?? ''})`);
      return 0;
    }

    if (action === 'fork') {
      const branchId =
        typeof values.branch === 'string' ? values.branch.trim() : positionals[2] ?? '';
      if (!branchId) {
        error('hebrah env cohorts fork: --branch <branch_id> is required');
        return 1;
      }
      const body: Record<string, unknown> = {};
      if (typeof values.name === 'string' && values.name.trim()) body.name = values.name.trim();
      if (values.count) body.count = parseInt(String(values.count), 10);
      if (typeof values.depth === 'string' && values.depth.trim()) body.depth = values.depth.trim();
      if (typeof values.conditions === 'string' && values.conditions.trim()) {
        body.condition_ids = values.conditions.split(',').map((s) => s.trim()).filter(Boolean);
      }
      const res = await api.post<Record<string, unknown>>(
        `/v1/environments/${safeEnv}/cohorts/branches/${safeId(branchId, 'branch_id')}/fork`,
        body
      );
      if (values.json) {
        json(res);
        return 0;
      }
      const br = (res.branch ?? {}) as Record<string, unknown>;
      success(`Forked branch ${bold(branchId)} -> ${bold(String(br.name ?? ''))} (${br.id ?? ''})`);
      return 0;
    }

    if (action === 'compare') {
      const left = typeof values.left === 'string' ? values.left.trim() : '';
      const right = typeof values.right === 'string' ? values.right.trim() : '';
      if (!left || !right) {
        error('hebrah env cohorts compare: --left <branch_id> and --right <branch_id> are required');
        return 1;
      }
      const res = await api.get<Record<string, unknown>>(
        `/v1/environments/${safeEnv}/cohorts/branches/compare`,
        { left, right }
      );
      if (values.json) {
        json(res);
        return 0;
      }
      console.log(bold(`Cohort Branch Comparison: ${left} vs. ${right}`));
      json(res);
      return 0;
    }

    const res = await api.get<Record<string, unknown>>(
      `/v1/environments/${safeEnv}/cohorts/branches`
    );
    if (values.json) {
      json(res);
      return 0;
    }
    const branches = Array.isArray(res.branches)
      ? (res.branches as Array<Record<string, unknown>>)
      : [];
    console.log(bold(`Cohort Branches (${branches.length}) — Environment ${sanitizeTerminalText(envId)}`));
    const headers = ['BRANCH ID', 'NAME', 'SPECIALTY PACK', 'DEPTH', 'PATIENTS'];
    const rows = branches.map((b) => [
      String(b.id ?? ''),
      String(b.name ?? ''),
      String(b.specialty_pack_id ?? ''),
      String(b.depth ?? 'standard'),
      String(b.patient_count ?? '')
    ]);
    table(headers, rows);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: cds-cascade (Point-of-Prescribing Cascade CDS Hook)
// ---------------------------------------------------------------------------

async function cdsCascadeEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      patient: { type: 'string' },
      'patient-id': { type: 'string' },
      rxnorm: { type: 'string' },
      medication: { type: 'string' },
      hook: { type: 'string', default: 'order-sign' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env cds-cascade: environment_id required');
    error(
      'Usage: hebrah env cds-cascade [environment_id] --patient <patient_id> [--rxnorm <code>] [--medication <display>] [--hook order-sign|order-select] [--json]'
    );
    return 1;
  }
  const patientId =
    typeof values.patient === 'string'
      ? values.patient.trim()
      : typeof values['patient-id'] === 'string'
        ? values['patient-id'].trim()
        : 'pat-001';

  const body: Record<string, unknown> = {
    hook: typeof values.hook === 'string' ? values.hook.trim() : 'order-sign',
    patient_id: patientId
  };
  if (typeof values.rxnorm === 'string' && values.rxnorm.trim()) {
    body.proposed_rxnorm = values.rxnorm.trim();
  }
  if (typeof values.medication === 'string' && values.medication.trim()) {
    body.proposed_display = values.medication.trim();
  }

  try {
    const res = await api.post<Record<string, unknown>>(
      `/v1/environments/${safeId(envId, 'environment_id')}/cds-hooks/prescribing-cascade`,
      body
    );
    if (values.json) {
      json(res);
      return 0;
    }
    const gt = (res.ground_truth ?? {}) as Record<string, unknown>;
    const cards = Array.isArray(res.cards) ? (res.cards as Array<Record<string, unknown>>) : [];
    const card0 = cards[0] ?? {};
    console.log(bold(`HL7 CDS Hooks 2.0 (${body.hook}) — Prescribing Cascade Evaluation`));
    console.log(dim('──────────────────────────────────────────────────────────────────'));
    kv([
      ['Environment ID', String(res.environment_id ?? envId)],
      ['Patient ID', String(res.patient_id ?? patientId)],
      ['Archetype ID', String(gt.archetype_id ?? 'n/a')],
      ['Cascade Class', gt.is_prescribing_cascade ? red('POSITIVE_CASCADE') : green('NEGATIVE_CONTROL')],
      ['CDS Card Indicator', String(card0.indicator ?? 'info')],
      ['CDS Card Summary', sanitizeTerminalText(String(card0.summary ?? ''))],
      ['eGFR (Creatinine vs Cystatin C)', `${gt.latest_egfr_creatinine ?? 'n/a'} vs ${gt.latest_egfr_cystatin_c ?? 'n/a'} mL/min/1.73m2`],
      ['Recommended Action', sanitizeTerminalText(String(gt.recommended_action ?? ''))]
    ]);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: x12-benchmark (CMS Medicare Utilization Benchmark)
// ---------------------------------------------------------------------------

async function x12BenchmarkEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const envId = resolveEnvId(positionals[0]);
  if (!envId) {
    error('hebrah env x12-benchmark: environment_id required');
    error('Usage: hebrah env x12-benchmark [environment_id] [--json]');
    return 1;
  }

  try {
    const res = await api.get<Record<string, unknown>>(
      `/v1/environments/${safeId(envId, 'environment_id')}/x12/benchmark`
    );
    if (values.json) {
      json(res);
      return 0;
    }
    console.log(bold(`CMS Medicare Utilization Benchmark (medicare_utilization_v1) — ${sanitizeTerminalText(envId)}`));
    kv([
      ['Total Claims Evaluated', String(res.total_claims ?? 0)],
      ['Denial Rate', `${res.environment_denial_rate_pct ?? 0}% (CMS National Ref: ${res.cms_national_denial_rate_pct ?? 0}%)`],
      ['Average Allowed Charge', String(res.average_allowed_usd ?? 'n/a')]
    ]);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Subcommand: fhir (Environment-scoped FHIR R4 Search)
// ---------------------------------------------------------------------------

async function fhirEnv(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      patient: { type: 'string' },
      'patient-id': { type: 'string' },
      count: { type: 'string', default: '50' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const knownTypes = new Set([
    'Patient',
    'Encounter',
    'Observation',
    'MedicationRequest',
    'Condition',
    'Claim',
    'AllergyIntolerance',
    'Procedure',
    'ImagingStudy',
    'DocumentReference',
    'DiagnosticReport',
    'Immunization',
    'CarePlan'
  ]);
  const firstIsType = positionals[0] && knownTypes.has(positionals[0]);
  const resourceType = firstIsType ? positionals[0] : (positionals[1] ?? 'Patient');
  const rawEnvArg = firstIsType ? positionals[1] : positionals[0];
  const envId = resolveEnvId(rawEnvArg);

  if (!envId) {
    error('hebrah env fhir: environment_id required');
    error('Usage: hebrah env fhir [environment_id] <ResourceType> [--patient <id>] [--count 50] [--json]');
    return 1;
  }

  const queryParams: Record<string, string> = {
    _count: typeof values.count === 'string' ? values.count : '50'
  };
  const patFilter =
    typeof values.patient === 'string'
      ? values.patient.trim()
      : typeof values['patient-id'] === 'string'
        ? values['patient-id'].trim()
        : '';
  if (patFilter) queryParams.patient = patFilter;

  try {
    const res = await api.get<Record<string, unknown>>(
      `/v1/environments/${safeId(envId, 'environment_id')}/fhir/${safeId(resourceType, 'resource_type')}`,
      queryParams
    );
    if (values.json) {
      json(res);
      return 0;
    }
    const entries = Array.isArray(res.entry) ? (res.entry as Array<Record<string, unknown>>) : [];
    console.log(
      bold(`FHIR R4 ${resourceType} Bundle (${res.total ?? entries.length} resources) — ${sanitizeTerminalText(envId)}`)
    );
    const headers = ['ID', 'RESOURCE TYPE', 'SUMMARY'];
    const rows = entries.slice(0, 25).map((e) => {
      const r = (e.resource ?? {}) as Record<string, unknown>;
      const summary =
        (r.medicationCodeableConcept as Record<string, unknown>)?.text ??
        (r.code as Record<string, unknown>)?.text ??
        ((Array.isArray(r.reasonCode) && (r.reasonCode[0] as Record<string, unknown>)?.text) || '') ??
        r.status ??
        '';
      return [String(r.id ?? ''), String(r.resourceType ?? resourceType), String(summary).slice(0, 56)];
    });
    table(headers, rows);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}
