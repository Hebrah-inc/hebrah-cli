// `hebrah relay` — manage customer-side relays.
//
// Subcommands:
//   hebrah relay enroll --target <pg-uri> --scopes <...> [--ttl 300]
//     Mint a one-shot enrollment JWT. Prints it for use with:
//       hebrah-relay install --token <jwt> --postgres-url <pg-uri>
//
//   hebrah relay list
//     List all enrolled relays for the current org, with cert + heartbeat status.
//
//   hebrah relay status <relay_id>
//     Show details for one relay: relay_id, target, latest cert, last heartbeat.
//
//   hebrah relay revoke <relay_id> [--reason <text>] [--yes]
//     Revoke all active certs for a relay. The relay's mTLS handshake
//     will fail on its next connection attempt.
//
// All subcommands require an authenticated account (hb_conn_* key from
// `hebrah login` or `hebrah signup`).

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { api } from '../api/client.js';
import { success, info, warn, error, json, table, dim, green, red, cyan, yellow } from '../output/format.js';
import { getArgv } from '../util/args.js';

// ---------------------------------------------------------------------------
// Shared types matching hebrah-api/app/connections/relay_routes.py
// ---------------------------------------------------------------------------

interface EnrollTokenResponse {
  token: string;
  jti: string;
  iat: number;
  exp: number;
  expires_in_seconds: number;
}

interface RelaySummary {
  relay_id: string;
  target_uri: string;
  connector: string;
  cert_serial: string;
  not_before: string;
  not_after: string;
  issued_at: string;
  revoked: boolean;
}

// ---------------------------------------------------------------------------
// Subcommand dispatch
// ---------------------------------------------------------------------------

export default async function relay(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  // Strip the subcommand name off the front so per-subcommand handlers
  // see only their own argv slice. The top-level parser in index.ts
  // forwards positionals[0] = 'relay' as the command name, but our
  // subcommand handlers expect argv that starts AFTER their name.
  const sub = argv.find((a) => !a.startsWith('-')) ?? args[0];
  const subIdx = sub ? argv.indexOf(sub) : -1;
  const subArgv = subIdx >= 0 ? argv.slice(subIdx + 1) : argv;

  switch (sub) {
    case 'enroll':
      return enroll(subArgv, { ...options, _argv: subArgv });
    case 'list':
    case 'ls':
      return listRelays(subArgv, { ...options, _argv: subArgv });
    case 'status':
    case 'show':
      return relayStatus(subArgv, { ...options, _argv: subArgv });
    case 'revoke':
      return revokeRelay(subArgv, { ...options, _argv: subArgv });
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      showHelp();
      return 0;
    default:
      error(`hebrah relay: unknown subcommand "${sub}"`);
      showHelp();
      return 1;
  }
}

function showHelp(): void {
  console.log(`hebrah relay — manage customer-side data relays

Subcommands:
  enroll              Mint an enrollment JWT for a new relay
  list (ls)           List relays for the current org
  status (show) <id>  Show details for one relay
  revoke <id>         Revoke a relay (kills its mTLS certs)

Run 'hebrah relay <subcommand> --help' for subcommand-specific options.

Examples:
  # 1. Mint an enrollment token (5-minute TTL by default)
  hebrah relay enroll --target 'postgresql://lattice-prod-01:5432/gl' \\
      --scopes 'gl:read,period:2025-Q4,accounts:1000-3999'

  # 2. Pass the token to the relay binary on the customer's network:
  hebrah-relay install --token <jwt-from-step-1> \\
      --postgres-url 'postgresql://lattice-prod-01:5432/gl'

  # 3. List your org's relays
  hebrah relay list

  # 4. Inspect one relay
  hebrah relay status relay_a1b2c3d4e5f6

  # 5. Cut off a compromised relay
  hebrah relay revoke relay_a1b2c3d4e5f6 --reason 'laptop stolen'
`);
}

// ---------------------------------------------------------------------------
// enroll
// ---------------------------------------------------------------------------

async function enroll(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? args;
  const { values } = parseArgs({
    args: argv,
    options: {
      target: { type: 'string' },
      'target-uri': { type: 'string' }, // alias
      scopes: { type: 'string' },
      connector: { type: 'string', default: 'postgres' },
      ttl: { type: 'string', default: '300' },
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false }
    },
    allowPositionals: false
  });

  if (values.help) {
    console.log(`hebrah relay enroll — mint a one-shot enrollment JWT

Usage:
  hebrah relay enroll --target <pg-uri> --scopes <scope1,scope2,...> [options]

Options:
  --target <uri>         Required. Database URI the relay will proxy to.
                          Alias: --target-uri.
  --scopes <csv>         Required. Comma-separated scope strings
                          (e.g. 'gl:read,period:2025-Q4,accounts:1000-3999').
  --connector <name>     Connector type. Default: postgres.
  --ttl <seconds>        Token TTL. Default: 300 (5 min).
  --json                 Output the token as JSON.
  -h, --help             Show this help.

The printed token is consumed once. Pipe it directly into:
  hebrah-relay install --token <token> --postgres-url <same-target>
`);
    return 0;
  }

  const targetUri = (values.target ?? values['target-uri']) as string | undefined;
  if (!targetUri) {
    error('hebrah relay enroll: --target required');
    error('Usage: hebrah relay enroll --target <pg-uri> --scopes <...>');
    return 1;
  }
  if (!values.scopes) {
    error('--scopes required (comma-separated)');
    error('Example: --scopes "gl:read,period:2025-Q4,accounts:1000-3999"');
    return 1;
  }

  const scopes = (values.scopes as string).split(',').map((s) => s.trim()).filter((s) => s.length > 0);
  if (scopes.length === 0) {
    error('--scopes must contain at least one non-empty scope');
    return 1;
  }

  const ttlSeconds = parseInt(values.ttl as string, 10);
  if (!Number.isFinite(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 3600) {
    error('--ttl must be between 60 and 3600 seconds');
    return 1;
  }

  try {
    const result = await api.post<EnrollTokenResponse>('/v1/relays/enroll-token', {
      target_uri: targetUri,
      connector: values.connector,
      allowed_scopes: scopes,
      allowed_tables: extractTablesFromScopes(scopes),
      ttl_seconds: ttlSeconds
    });

    if (values.json) {
      json(result);
      return 0;
    }

    console.log(green('✓ Enrollment token minted.'));
    console.log('');
    console.log(`  ${dim('Target:')}  ${targetUri}`);
    console.log(`  ${dim('Scopes:')}  ${scopes.join(', ')}`);
    console.log(`  ${dim('Expires:')} in ${result.expires_in_seconds}s (${new Date(result.exp * 1000).toISOString()})`);
    console.log('');
    console.log(cyan('Token (single-use, 5-min TTL):'));
    console.log(`  ${result.token}`);
    console.log('');
    console.log(dim('Next: pipe to the relay binary on the customer network:'));
    console.log(dim(`  hebrah-relay install \\`));
    console.log(dim(`    --token '${result.token}' \\`));
    console.log(dim(`    --postgres-url '${targetUri}'`));
    console.log('');
    return 0;
  } catch (err: any) {
    if (err.suggestion) {
      error(`hebrah relay enroll: ${err.message}`);
      error(`Hint: ${err.suggestion}`);
    } else {
      error(`hebrah relay enroll: ${err.message ?? 'unknown error'}`);
    }
    return 4;
  }
}

/**
 * Extract table names from scope strings like "table:accounts" or "gl:read".
 * Used to populate `allowed_tables` so the relay's scope validation passes.
 */
function extractTablesFromScopes(scopes: string[]): string[] {
  const tables = new Set<string>();
  for (const s of scopes) {
    // "table:accounts" form (MVP SQLite-style)
    if (s.startsWith('table:')) {
      tables.add(s.substring('table:'.length));
      continue;
    }
    // "gl:read" / "gl:write" form (table:access) — table name is the part before ':'
    if (s.endsWith(':read') || s.endsWith(':write')) {
      const table = s.replace(/:(read|write)$/, '');
      if (table.length > 0) tables.add(table);
      continue;
    }
    // "database:<id>" form (workspace pack) — table name comes from the catalog
    if (s.startsWith('database:')) {
      tables.add(s.substring('database:'.length));
    }
  }
  return Array.from(tables);
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

async function listRelays(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? args;
  const { values } = parseArgs({
    args: argv,
    options: {
      all: { type: 'boolean', default: false },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  try {
    const relays = await api.get<RelaySummary[]>('/v1/relays');

    const filtered = values.all ? relays : relays.filter((r) => !r.revoked);

    if (values.json) {
      json(filtered);
      return 0;
    }

    if (filtered.length === 0) {
      console.log(dim('(no relays enrolled)'));
      console.log(dim('Start one: hebrah relay enroll --target <pg-uri> --scopes <...>'));
      return 0;
    }

    const rows = filtered.map((r) => [
      r.relay_id,
      truncate(r.target_uri, 32),
      r.connector,
      r.cert_serial.substring(0, 12) + '…',
      formatDate(r.not_after),
      r.revoked ? red('revoked') : green('active')
    ]);

    table(['RELAY_ID', 'TARGET', 'CONN', 'CERT_SERIAL', 'EXPIRES', 'STATUS'], rows);
    console.log('');
    console.log(dim(`${filtered.length} relay(s)${values.all ? ' (all)' : ' (active only — pass --all to include revoked)'}`));
    console.log(dim('Details: hebrah relay status <relay_id>'));
    return 0;
  } catch (err: any) {
    error(`hebrah relay list: ${err.message ?? 'unknown error'}`);
    return 4;
  }
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

async function relayStatus(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? args;
  const relayId = argv.find((a) => !a.startsWith('-')) ?? args[0];
  if (!relayId) {
    error('hebrah relay status: relay_id required');
    error('Usage: hebrah relay status <relay_id>');
    return 1;
  }
  // Strip the relay_id positional before parseArgs so it doesn't trip
  // allowPositionals:false.
  const flagsOnly = argv.filter((a) => a !== relayId);

  const { values } = parseArgs({
    args: flagsOnly,
    options: { json: { type: 'boolean', default: false } },
    allowPositionals: false
  });

  try {
    const relays = await api.get<RelaySummary[]>('/v1/relays');
    const matches = relays.filter((r) => r.relay_id === relayId);
    if (matches.length === 0) {
      warn(`hebrah relay status: relay "${relayId}" not found in your org`);
      return 4;
    }

    if (values.json) {
      json(matches[0]);
      return 0;
    }

    const r = matches[0];
    console.log(`Relay ${cyan(r.relay_id)}`);
    console.log('');
    console.log(`  ${dim('Target:')}       ${r.target_uri}`);
    console.log(`  ${dim('Connector:')}    ${r.connector}`);
    console.log(`  ${dim('Cert serial:')}  ${r.cert_serial}`);
    console.log(`  ${dim('Issued:')}       ${formatDate(r.issued_at)}`);
    console.log(`  ${dim('Not before:')}   ${formatDate(r.not_before)}`);
    console.log(`  ${dim('Not after:')}    ${formatDate(r.not_after)}  ${certFreshnessLabel(r.not_after)}`);
    console.log(`  ${dim('Status:')}       ${r.revoked ? red('revoked') : green('active')}`);

    // If multiple cert rows for the same relay (from prior rotations), show them all
    if (matches.length > 1) {
      console.log('');
      console.log(dim(`  (${matches.length} cert rows for this relay — showing latest; pass --all to list)`));
    }
    return 0;
  } catch (err: any) {
    error(`hebrah relay status: ${err.message ?? 'unknown error'}`);
    return 4;
  }
}

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------

async function revokeRelay(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? args;
  const relayId = argv.find((a) => !a.startsWith('-')) ?? args[0];
  if (!relayId) {
    error('hebrah relay revoke: relay_id required');
    error('Usage: hebrah relay revoke <relay_id> [--reason <text>] [--yes]');
    return 1;
  }
  const flagsOnly = argv.filter((a) => a !== relayId);

  const { values } = parseArgs({
    args: flagsOnly,
    options: {
      reason: { type: 'string' },
      yes: { type: 'boolean', short: 'y', default: false }
    },
    allowPositionals: false
  });

  try {
    // Safety: confirm before destructive action
    const skipConfirm = values.yes === true || !input.isTTY;
    if (!skipConfirm) {
      warn(`This will REVOKE all active certs for relay ${relayId}.`);
      warn('The relay\'s mTLS handshake will fail on its next connection attempt.');
      warn('In-flight queries will fail. This is irreversible.');
      if (values.reason) {
        console.log(dim(`  reason: ${values.reason}`));
      }
      const rl = createInterface({ input, output });
      const answer = await rl.question('Type the relay_id to confirm: ');
      rl.close();
      if (answer.trim() !== relayId) {
        warn('Revoke aborted (input did not match).');
        return 1;
      }
    }

    await api.delete(`/v1/relays/${relayId}`);
    success(`✓ Relay ${relayId} revoked.`);
    console.log(dim('  (the relay will fail its next mTLS handshake; new certs cannot be minted)'));
    return 0;
  } catch (err: any) {
    if (err.statusCode === 404) {
      warn(`hebrah relay revoke: relay "${relayId}" not found in your org`);
      return 4;
    }
    error(`hebrah relay revoke: ${err.message ?? 'unknown error'}`);
    return 4;
  }
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const now = Date.now();
  const ms = d.getTime() - now;
  const days = Math.round(ms / (1000 * 60 * 60 * 24));
  return `${d.toISOString().replace('T', ' ').substring(0, 19)} UTC (${days >= 0 ? 'in ' : ''}${Math.abs(days)}d${days >= 0 ? '' : ' ago'})`;
}

function certFreshnessLabel(notAfter: string): string {
  const d = new Date(notAfter).getTime();
  const days = Math.round((d - Date.now()) / (1000 * 60 * 60 * 24));
  if (days < 0) return red(`(EXPIRED ${-days}d ago)`);
  if (days < 7) return yellow(`(expires in ${days}d)`);
  return green(`(valid)`);
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.substring(0, n - 1) + '…';
}