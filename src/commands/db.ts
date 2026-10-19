/**
 * `hebrah db` — Database Tunnel, Local PostgreSQL Proxy, WireGuard VPN & SQL Command Suite
 *
 * Subcommands:
 *   hebrah db proxy [env_id] [port]     Start a local PostgreSQL v3 wire-protocol tunnel on 127.0.0.1:<port>
 *   hebrah db wireguard [env_id]        Export valid WireGuard VPN .conf (or bring tunnel up with --up)
 *   hebrah db query [env_id] "<sql>"    Run a read-only SQL query against the environment database
 *   hebrah db tables [env_id]           List tables & row counts in the environment database
 *   hebrah db status [env_id]           Show database & tunnel status for an environment
 */

import { parseArgs } from 'node:util';
import { resolve as resolvePath, basename } from 'node:path';
import { spawnSync } from 'node:child_process';
import { api, safeId } from '../api/client.js';
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
  cyan,
  yellow,
  formatBytes,
  sanitizeTerminalText,
  redactSecrets
} from '../output/format.js';
import { getArgv } from '../util/args.js';
import {
  generateEphemeralPgPassword,
  isPortAvailable,
  startPgWireProxy
} from '../util/pgProxy.js';
import {
  type EnvironmentSummary,
  normalizeWireguardKey,
  normalizeWireguardConfig,
  normalizeWireguardFilename,
  redactWireguardPrivateKey,
  writeWireguardConfigFile,
  ensureEnvironmentOrigin,
  resolveEnvironmentId
} from '../util/wireguard.js';

export {
  normalizeWireguardKey,
  normalizeWireguardConfig,
  normalizeWireguardFilename,
  redactWireguardPrivateKey,
  writeWireguardConfigFile,
  ensureEnvironmentOrigin
};

interface WireguardConfigResult {
  environment_id: string;
  filename?: string;
  config_filename?: string;
  client_ip: string;
  server_endpoint: string;
  db_schema?: string;
  config?: string;
  config_text?: string;
  instructions?: string;
}

interface DbQueryResult {
  environment_id: string;
  addon: string;
  rows: Record<string, unknown>[];
  row_count: number;
  bytes_egressed: number;
  duration_ms: number;
}

function showDbHelp(): void {
  console.log(`hebrah db — Database tunnel, local PostgreSQL proxy, WireGuard VPN & SQL tools

Usage:
  hebrah db proxy [env_id] [port]              Start local PostgreSQL wire-protocol proxy (default: 5432)
  hebrah db wireguard [env_id] [--out <file>]  Export valid WireGuard VPN .conf (aliases: vpn, tunnel, wg)
  hebrah db query [env_id] "<sql>"             Run read-only SQL query against attached database
  hebrah db tables [env_id]                    List tables and row counts in attached database
  hebrah db status [env_id]                    Show database endpoints & VPN coordinates

Options:
  --port, -p <port>        Local TCP port for "hebrah db proxy" (default: 5432, auto-falls back to 15432 if busy)
  --no-auth                Disable ephemeral per-session password authentication on 127.0.0.1 proxy
  --no-listen              Print GUI connection coordinates and exit without keeping TCP listener open
  --out, -o <path>         Write WireGuard .conf to file (chmod 0600) instead of stdout
  --up                     Immediately activate WireGuard tunnel via wg-quick or WireGuard.app
  --reveal-private-key     Print unredacted WireGuard PrivateKey when writing to stdout
  --addon <type>           Database module for "query" (default: postgres)
  --json                   Emit machine-readable JSON

Examples:
  hebrah db proxy e858732a-828d-418b-ab48-4189d8a5cc04 5432
  hebrah db wireguard e858732a-828d-418b-ab48-4189d8a5cc04 --out ./hb-env.conf
  hebrah db query e858732a-828d-418b-ab48-4189d8a5cc04 "SELECT id, mrn, first_name, last_name FROM patients LIMIT 5"
  hebrah db tables e858732a-828d-418b-ab48-4189d8a5cc04
`);
}

export default async function dbCommand(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const fullArgv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: fullArgv,
    options: {
      port: { type: 'string', short: 'p' },
      'no-auth': { type: 'boolean', default: false },
      listen: { type: 'boolean' },
      'no-listen': { type: 'boolean' },
      out: { type: 'string', short: 'o' },
      up: { type: 'boolean', default: false },
      'reveal-private-key': { type: 'boolean', default: false },
      'client-name': { type: 'string', default: 'cli-developer-workstation' },
      addon: { type: 'string', default: 'postgres' },
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const sub = positionals[0];
  if (values.help || !sub || sub === 'help') {
    showDbHelp();
    return 0;
  }

  try {
    // ------------------------------------------------------------------
    // 1. hebrah db proxy [env_id] [port]
    // ------------------------------------------------------------------
    if (sub === 'proxy' || sub === 'db-proxy' || sub === 'connect') {
      let rawEnvId: string | undefined = positionals[1];
      let rawPositionalPort: string | undefined = positionals[2];

      if (rawEnvId && /^\d{2,5}$/.test(rawEnvId) && !rawPositionalPort) {
        rawPositionalPort = rawEnvId;
        rawEnvId = undefined;
      }

      const envId = await resolveEnvironmentId(rawEnvId, options);
      const requestedPort = Number.parseInt(
        String(values.port ?? rawPositionalPort ?? '5432'),
        10
      );
      if (
        Number.isNaN(requestedPort) ||
        requestedPort < 1 ||
        requestedPort > 65535
      ) {
        error(`Invalid port: ${String(values.port ?? rawPositionalPort)}`);
        return 1;
      }

      let bindPort = requestedPort;
      const portFree = await isPortAvailable(bindPort);
      let fellBackFromBusyPort = false;
      if (!portFree) {
        const fallback = requestedPort === 5432 ? 15432 : requestedPort + 10000;
        if (fallback <= 65535 && (await isPortAvailable(fallback))) {
          bindPort = fallback;
          fellBackFromBusyPort = true;
        }
      }

      const shortDb = `clinic_${envId.replace(/-/g, '_').slice(0, 12)}`;
      const disableAuth = Boolean(values['no-auth']);
      const ephemeralPassword = disableAuth ? null : generateEphemeralPgPassword();
      const connectionInfo = {
        environment_id: envId,
        host: '127.0.0.1',
        port: bindPort,
        database: shortDb,
        user: 'hebrah_readonly',
        password: ephemeralPassword,
        auth_mode: ephemeralPassword ? 'ephemeral_password' : 'none',
        ssl_mode: 'disable',
        jdbc_url: `jdbc:postgresql://127.0.0.1:${bindPort}/${shortDb}`,
        connection_string: `postgresql://hebrah_readonly@127.0.0.1:${bindPort}/${shortDb}?sslmode=disable`
      };

      const shouldSkipListener =
        Boolean(values['no-listen']) ||
        Boolean(values.json) ||
        (Boolean(process.env.VITEST) && !values.listen);

      if (values.json) {
        json(connectionInfo);
        return 0;
      }

      success(
        `Hebrah Local Database Proxy Coordinates (DBeaver / TablePlus / DataGrip / psql)`
      );
      console.log();
      if (fellBackFromBusyPort) {
        warn(
          `Port ${requestedPort} is already in use on 127.0.0.1 (e.g. local PostgreSQL). Bound to port ${bold(String(bindPort))} instead.`
        );
        console.log();
      }
      kv([
        ['Environment ID', cyan(connectionInfo.environment_id)],
        ['Host', connectionInfo.host],
        ['Port', bold(String(connectionInfo.port))],
        ['Database', connectionInfo.database],
        ['Username', connectionInfo.user],
        [
          'Password',
          ephemeralPassword
            ? `${bold(ephemeralPassword)} ${dim('(ephemeral per-session token)')}`
            : dim('(disabled via --no-auth)')
        ],
        ['JDBC URL', cyan(connectionInfo.jdbc_url)],
        ['Connection URL', cyan(connectionInfo.connection_string)],
        [
          'psql Quickstart',
          ephemeralPassword
            ? `PGPASSWORD=${ephemeralPassword} psql "${connectionInfo.connection_string}"`
            : `psql "${connectionInfo.connection_string}"`
        ]
      ]);

      if (shouldSkipListener) {
        return 0;
      }

      const proxyHandle = await startPgWireProxy({
        envId,
        port: bindPort,
        database: shortDb,
        password: ephemeralPassword,
        requirePassword: !disableAuth,
        client: api,
        onQuery: (sqlText, rowCount, durationMs) => {
          const safeSql = redactSecrets(sanitizeTerminalText(sqlText));
          const preview = safeSql.replace(/\s+/g, ' ').slice(0, 90);
          console.log(
            `  ${dim(`[${new Date().toISOString().slice(11, 19)}]`)} ${cyan('SQL')} ${preview}${safeSql.length > 90 ? '…' : ''} ${dim(`→ ${rowCount} rows (${durationMs}ms)`)}`
          );
        }
      });

      console.log();
      console.log(
        `${green('●')} Listening on ${bold(`${proxyHandle.host}:${proxyHandle.port}`)} (PostgreSQL v3 wire protocol) — press ${bold('Ctrl+C')} to close tunnel.`
      );
      console.log();

      await new Promise<void>((resolve) => {
        const shutdown = () => {
          console.log();
          console.log(dim('Closing local PostgreSQL proxy tunnel...'));
          void proxyHandle.close().finally(() => resolve());
        };
        process.once('SIGINT', shutdown);
        process.once('SIGTERM', shutdown);
      });

      return 0;
    }

    // ------------------------------------------------------------------
    // 2. hebrah db wireguard [env_id] [--out <file>] [--up]
    // ------------------------------------------------------------------
    if (
      sub === 'wireguard' ||
      sub === 'vpn' ||
      sub === 'tunnel' ||
      sub === 'wg'
    ) {
      const envId = await resolveEnvironmentId(positionals[1], options);
      const clientName = String(
        values['client-name'] || 'cli-developer-workstation'
      );
      const wg = await api.get<WireguardConfigResult>(
        `/v1/environments/${safeId(envId, 'environment_id')}/wireguard/config`,
        {
          client_name: clientName,
          download: 'true'
        }
      );

      const configText = normalizeWireguardConfig(wg.config_text || wg.config || '');
      const filename = normalizeWireguardFilename(
        wg.filename || wg.config_filename,
        envId
      );
      const revealKey = Boolean(values['reveal-private-key']);

      let outPath = typeof values.out === 'string' ? values.out : undefined;
      if (values.up && !outPath) {
        outPath = resolvePath(process.cwd(), filename);
      }

      if (outPath) {
        const resolved = writeWireguardConfigFile(outPath, configText);

        if (values.json) {
          const safeConfig = revealKey
            ? configText
            : redactWireguardPrivateKey(configText);
          json({
            ...wg,
            config: safeConfig,
            config_text: safeConfig,
            saved_to: resolved,
            mode: '0600'
          });
          return 0;
        }

        success(
          `WireGuard configuration written to ${bold(resolved)} (permissions 0600)`
        );
        console.log();
        info(
          `Import ${basename(resolved)} into WireGuard.app or run: "sudo wg-quick up ${resolved}"`
        );
        info(
          `Or connect immediately without a kernel VPN daemon using: "hebrah db proxy ${envId} 5432"`
        );

        if (values.up) {
          const wgCheck = spawnSync('which', ['wg-quick'], {
            encoding: 'utf8'
          });
          if (wgCheck.status === 0) {
            console.log();
            info('Bringing up WireGuard interface via wg-quick...');
            const upRes = spawnSync('wg-quick', ['up', resolved], {
              stdio: 'inherit'
            });
            if (upRes.status !== 0) {
              warn(
                `Could not start wg-quick without root privileges. Run "sudo wg-quick up ${resolved}" or use "hebrah db proxy ${envId} 5432".`
              );
            }
          } else if (process.platform === 'darwin') {
            console.log();
            info(`Opening ${basename(resolved)} in macOS WireGuard client...`);
            spawnSync('open', [resolved], { stdio: 'ignore' });
          }
        }
        return 0;
      }

      if (values.json) {
        const safeConfig = revealKey
          ? configText
          : redactWireguardPrivateKey(configText);
        json({
          ...wg,
          config: safeConfig,
          config_text: safeConfig
        });
        return 0;
      }

      console.log(bold(`WireGuard Mesh Tunnel Config — ${envId} (${filename}):`));
      console.log(
        dim('──────────────────────────────────────────────────────────────────')
      );
      console.log(
        sanitizeTerminalText(
          revealKey ? configText : redactWireguardPrivateKey(configText)
        )
      );
      console.log(
        dim('──────────────────────────────────────────────────────────────────')
      );
      console.log();
      info(
        `Save an importable .conf file with "--out ./${filename}" (writes with 0600 permissions), or run "hebrah db proxy ${envId} 5432" for a local TCP proxy.`
      );
      return 0;
    }

    // ------------------------------------------------------------------
    // 3. hebrah db query [env_id] "<sql>"
    // ------------------------------------------------------------------
    if (sub === 'query' || sub === 'sql') {
      let rawEnvId: string | undefined;
      let sqlText: string | undefined;

      if (positionals.length >= 3) {
        rawEnvId = positionals[1];
        sqlText = positionals.slice(2).join(' ');
      } else if (positionals.length === 2) {
        const arg1 = positionals[1]!;
        if (/^\s*(SELECT|WITH|SHOW|EXPLAIN|PRAGMA|MATCH)\b/i.test(arg1)) {
          sqlText = arg1;
        } else {
          error(
            'hebrah db query: SQL query string required. Usage: hebrah db query [env_id] "SELECT * FROM patients LIMIT 5"'
          );
          return 1;
        }
      } else {
        error(
          'hebrah db query: SQL query string required. Usage: hebrah db query [env_id] "SELECT * FROM patients LIMIT 5"'
        );
        return 1;
      }

      const envId = await resolveEnvironmentId(rawEnvId, options);
      const addon = typeof values.addon === 'string' ? values.addon : 'postgres';

      const res = await api.post<DbQueryResult>(
        `/v1/environments/${safeId(envId, 'environment_id')}/db/query`,
        {
          sql: sqlText,
          addon,
          actor_type: 'agent'
        }
      );

      if (values.json) {
        json(res);
        return 0;
      }

      if (res.rows && res.rows.length > 0) {
        const headers = Object.keys(res.rows[0]!);
        const rows = res.rows.map((r) =>
          headers.map((h) => String(r[h] ?? ''))
        );
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
    }

    // ------------------------------------------------------------------
    // 4. hebrah db tables [env_id]
    // ------------------------------------------------------------------
    if (sub === 'tables' || sub === 'schema') {
      const envId = await resolveEnvironmentId(positionals[1], options);
      const res = await api.get<{
        environment_id: string;
        schema?: string;
        tables: Array<{
          name: string;
          schema: string;
          row_count: number;
          description?: string;
        }>;
      }>(`/v1/environments/${safeId(envId, 'environment_id')}/db/tables`);

      if (values.json) {
        json(res);
        return 0;
      }

      const tables = res.tables ?? [];
      console.log(
        bold(
          `Attached Database Tables — Environment ${sanitizeTerminalText(String(res.environment_id || envId))}`
        )
      );
      console.log();
      table(
        ['SCHEMA', 'TABLE', 'ROWS', 'DESCRIPTION'],
        tables.map((t) => [
          t.schema || 'public',
          t.name,
          String(t.row_count ?? 0),
          t.description || ''
        ])
      );
      return 0;
    }

    // ------------------------------------------------------------------
    // 5. hebrah db status [env_id]
    // ------------------------------------------------------------------
    if (sub === 'status' || sub === 'info') {
      const envId = await resolveEnvironmentId(positionals[1], options);
      const env = await api.get<EnvironmentSummary>(
        `/v1/environments/${safeId(envId, 'environment_id')}`
      );
      if (values.json) {
        json(env);
        return 0;
      }

      const shortDb = `clinic_${env.id.replace(/-/g, '_').slice(0, 12)}`;
      console.log(bold('Isolated Environment Database Status'));
      console.log();
      kv([
        ['Environment ID', cyan(env.id)],
        ['Name', bold(env.name)],
        [
          'Status',
          env.status === 'active' || env.status === 'running'
            ? green(env.status)
            : yellow(env.status)
        ],
        ['Attached Add-ons', (env.addons ?? env.database_packs ?? ['postgres']).join(', ')],
        ['Local Proxy Command', cyan(`hebrah db proxy ${env.id} 5432`)],
        [
          'WireGuard Export',
          cyan(
            `hebrah db wireguard ${env.id} --out ./hb-env-${env.id.slice(0, 8)}.conf`
          )
        ],
        ['Default Database', shortDb]
      ]);
      return 0;
    }

    error(
      `hebrah db: unknown subcommand "${sub}". Run "hebrah db --help" for usage.`
    );
    return 1;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}
