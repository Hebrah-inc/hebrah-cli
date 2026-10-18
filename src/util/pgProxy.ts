/**
 * Local PostgreSQL v3 Wire-Protocol Proxy (`hebrah db proxy <env_id> [port]`)
 *
 * Allows desktop SQL GUIs (DBeaver, TablePlus, DataGrip, Postico) and `psql`
 * to connect directly to `127.0.0.1:<port>` without requiring a kernel-level
 * WireGuard VPN interface. Translates PostgreSQL v3 frontend/backend protocol
 * frames into authenticated HTTPS calls to `/v1/environments/{id}/db/query`
 * and `/v1/environments/{id}/db/tables`.
 */

import * as net from 'node:net';
import { api, safeId } from '../api/client.js';

export type PgProxyClient = typeof api;

export interface PgProxyOptions {
  envId: string;
  port: number;
  host?: string;
  database?: string;
  client?: PgProxyClient;
  onQuery?: (sql: string, rowCount: number, durationMs: number) => void;
  onError?: (err: Error) => void;
}

export interface PgProxyHandle {
  host: string;
  port: number;
  close: () => Promise<void>;
}

interface QueryResultShape {
  columns: string[];
  rows: Array<Array<unknown>>;
  commandTag: string;
}

interface TableColumnMeta {
  name: string;
  type?: string;
  nullable?: boolean;
}

interface TableMeta {
  name: string;
  schema?: string;
  row_count?: number;
  columns?: TableColumnMeta[];
  description?: string;
}

function buildBackendPacket(typeChar: string, payload: Buffer): Buffer {
  const buf = Buffer.alloc(1 + 4 + payload.length);
  buf.write(typeChar, 0, 1, 'ascii');
  buf.writeInt32BE(payload.length + 4, 1);
  payload.copy(buf, 5);
  return buf;
}

function cstr(value: string): Buffer {
  return Buffer.from(`${value}\0`, 'utf8');
}

function buildParameterStatus(name: string, value: string): Buffer {
  return buildBackendPacket('S', Buffer.concat([cstr(name), cstr(value)]));
}

function buildAuthenticationOk(): Buffer {
  const payload = Buffer.alloc(4);
  payload.writeInt32BE(0, 0);
  return buildBackendPacket('R', payload);
}

function buildBackendKeyData(pid = 4242, secret = 1337): Buffer {
  const payload = Buffer.alloc(8);
  payload.writeInt32BE(pid, 0);
  payload.writeInt32BE(secret, 4);
  return buildBackendPacket('K', payload);
}

function buildReadyForQuery(txStatus: 'I' | 'T' | 'E' = 'I'): Buffer {
  return buildBackendPacket('Z', Buffer.from(txStatus, 'ascii'));
}

function buildRowDescription(columns: string[]): Buffer {
  const countBuf = Buffer.alloc(2);
  countBuf.writeInt16BE(columns.length, 0);
  const fieldBuffers: Buffer[] = [countBuf];

  for (let i = 0; i < columns.length; i++) {
    const colName = columns[i] || `col_${i + 1}`;
    const nameBuf = cstr(colName);
    const meta = Buffer.alloc(18);
    meta.writeInt32BE(0, 0); // table OID
    meta.writeInt16BE(i + 1, 4); // column attr number
    meta.writeInt32BE(25, 6); // type OID: 25 = TEXT
    meta.writeInt16BE(-1, 10); // data type size (-1 variable)
    meta.writeInt32BE(-1, 12); // type modifier
    meta.writeInt16BE(0, 16); // format code (0 = text)
    fieldBuffers.push(nameBuf, meta);
  }

  return buildBackendPacket('T', Buffer.concat(fieldBuffers));
}

function buildDataRow(row: Array<unknown>): Buffer {
  const countBuf = Buffer.alloc(2);
  countBuf.writeInt16BE(row.length, 0);
  const parts: Buffer[] = [countBuf];

  for (const val of row) {
    if (val === null || val === undefined) {
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeInt32BE(-1, 0);
      parts.push(lenBuf);
    } else {
      const strVal =
        typeof val === 'object' ? JSON.stringify(val) : String(val);
      const valBuf = Buffer.from(strVal, 'utf8');
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeInt32BE(valBuf.length, 0);
      parts.push(lenBuf, valBuf);
    }
  }

  return buildBackendPacket('D', Buffer.concat(parts));
}

function buildCommandComplete(tag: string): Buffer {
  return buildBackendPacket('C', cstr(tag));
}

function buildEmptyQueryResponse(): Buffer {
  return buildBackendPacket('I', Buffer.alloc(0));
}

function buildParseComplete(): Buffer {
  return buildBackendPacket('1', Buffer.alloc(0));
}

function buildBindComplete(): Buffer {
  return buildBackendPacket('2', Buffer.alloc(0));
}

function buildCloseComplete(): Buffer {
  return buildBackendPacket('3', Buffer.alloc(0));
}

function buildNoData(): Buffer {
  return buildBackendPacket('n', Buffer.alloc(0));
}

function buildParameterDescription(paramCount = 0): Buffer {
  const buf = Buffer.alloc(2 + paramCount * 4);
  buf.writeInt16BE(paramCount, 0);
  for (let i = 0; i < paramCount; i++) {
    buf.writeInt32BE(25, 2 + i * 4);
  }
  return buildBackendPacket('t', buf);
}

function buildErrorResponse(message: string, code = '42000'): Buffer {
  const parts = [
    Buffer.from('S', 'ascii'),
    cstr('ERROR'),
    Buffer.from('V', 'ascii'),
    cstr('ERROR'),
    Buffer.from('C', 'ascii'),
    cstr(code),
    Buffer.from('M', 'ascii'),
    cstr(message),
    Buffer.from('\0', 'ascii')
  ];
  return buildBackendPacket('E', Buffer.concat(parts));
}

/**
 * Normalizes API response from `/v1/environments/{id}/db/query` into columns + rows
 */
function normalizeApiQueryResult(raw: unknown): QueryResultShape {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const rawRows = Array.isArray(obj.rows) ? obj.rows : [];
  let columns: string[] = Array.isArray(obj.columns)
    ? (obj.columns as unknown[]).map((c) =>
        typeof c === 'object' && c !== null && 'name' in c
          ? String((c as { name: unknown }).name)
          : String(c)
      )
    : [];

  if (
    columns.length === 0 &&
    rawRows.length > 0 &&
    typeof rawRows[0] === 'object' &&
    rawRows[0] !== null &&
    !Array.isArray(rawRows[0])
  ) {
    columns = Object.keys(rawRows[0] as Record<string, unknown>);
  }

  const rows: Array<Array<unknown>> = rawRows.map((r) => {
    if (Array.isArray(r)) return r;
    if (typeof r === 'object' && r !== null) {
      const rec = r as Record<string, unknown>;
      return columns.map((col) => rec[col]);
    }
    return [r];
  });

  return {
    columns,
    rows,
    commandTag: `SELECT ${rows.length}`
  };
}

/**
 * Handles synthetic PostgreSQL metadata queries emitted by DBeaver, TablePlus, DataGrip, and psql
 * before falling through to the remote Isolated Health Environment query endpoint.
 */
async function executeSqlStatement(
  sqlText: string,
  envId: string,
  databaseName: string,
  client: PgProxyClient
): Promise<QueryResultShape> {
  const trimmed = sqlText.trim().replace(/;+\s*$/, '').trim();
  const upper = trimmed.toUpperCase();

  if (!trimmed) {
    return { columns: [], rows: [], commandTag: 'SELECT 0' };
  }

  // Transaction & session control commands sent by GUI clients on connect
  if (
    upper.startsWith('SET ') ||
    upper.startsWith('RESET ') ||
    upper === 'BEGIN' ||
    upper === 'START TRANSACTION' ||
    upper === 'COMMIT' ||
    upper === 'END' ||
    upper === 'ROLLBACK' ||
    upper.startsWith('DEALLOCATE') ||
    upper.startsWith('DISCARD') ||
    upper.startsWith('UNLISTEN')
  ) {
    const cmd = upper.split(/\s+/)[0] || 'SET';
    return { columns: [], rows: [], commandTag: cmd };
  }

  if (upper.startsWith('SHOW ')) {
    const setting = trimmed.slice(5).trim().toLowerCase();
    const defaults: Record<string, string> = {
      transaction_isolation: 'read committed',
      standard_conforming_strings: 'on',
      client_encoding: 'UTF8',
      server_encoding: 'UTF8',
      server_version: '16.4 (Hebrah Isolated Clinic Runtime)',
      server_version_num: '160004',
      search_path: 'public',
      timezone: 'UTC',
      is_superuser: 'off',
      session_authorization: 'hebrah_readonly',
      max_identifier_length: '63'
    };
    const val = defaults[setting] ?? 'on';
    return {
      columns: [setting],
      rows: [[val]],
      commandTag: 'SHOW'
    };
  }

  if (upper === 'SELECT 1' || upper === 'SELECT 1 AS TEST') {
    return {
      columns: ['?column?'],
      rows: [[1]],
      commandTag: 'SELECT 1'
    };
  }

  if (upper.includes('VERSION()') && !upper.includes('FROM ')) {
    return {
      columns: ['version'],
      rows: [
        [
          'PostgreSQL 16.4 (Hebrah Isolated Clinic Environment Proxy) on aarch64-unknown-linux-gnu'
        ]
      ],
      commandTag: 'SELECT 1'
    };
  }

  if (
    (upper.includes('CURRENT_DATABASE()') ||
      upper.includes('CURRENT_SCHEMA()') ||
      upper.includes('CURRENT_USER') ||
      upper.includes('SESSION_USER')) &&
    !upper.includes('FROM ')
  ) {
    return {
      columns: [
        'current_database',
        'current_schema',
        'current_user',
        'session_user'
      ],
      rows: [[databaseName, 'public', 'hebrah_readonly', 'hebrah_readonly']],
      commandTag: 'SELECT 1'
    };
  }

  // Introspection queries (`\dt`, `pg_catalog.pg_tables`, `information_schema.tables`, `pg_namespace`, `information_schema.columns`)
  if (
    upper.includes('PG_CATALOG.PG_NAMESPACE') ||
    upper.includes('INFORMATION_SCHEMA.SCHEMATA')
  ) {
    return {
      columns: ['oid', 'nspname', 'schema_name', 'nspowner'],
      rows: [
        [2200, 'public', 'public', 10],
        [11, 'pg_catalog', 'pg_catalog', 10],
        [13000, 'information_schema', 'information_schema', 10]
      ],
      commandTag: 'SELECT 3'
    };
  }

  if (
    upper.includes('PG_CATALOG.PG_DATABASE') ||
    upper.includes(' FROM PG_DATABASE')
  ) {
    return {
      columns: ['oid', 'datname', 'encoding', 'datistemplate', 'datallowconn'],
      rows: [[16384, databaseName, 6, 'f', 't']],
      commandTag: 'SELECT 1'
    };
  }

  if (
    upper.includes('INFORMATION_SCHEMA.COLUMNS') ||
    upper.includes('PG_CATALOG.PG_ATTRIBUTE')
  ) {
    try {
      const tablesResp = await client.get<{ tables?: TableMeta[] }>(
        `/v1/environments/${safeId(envId, 'environment_id')}/db/tables`
      );
      const tableList: TableMeta[] = Array.isArray(tablesResp?.tables) ? tablesResp.tables : [];
      const colRows: Array<Array<unknown>> = [];
      for (const tbl of tableList) {
        const cols: TableColumnMeta[] = Array.isArray(tbl.columns) ? tbl.columns : [];
        cols.forEach((col: TableColumnMeta, idx: number) => {
          colRows.push([
            'public',
            tbl.name,
            col.name,
            idx + 1,
            col.type || 'text',
            col.nullable !== false ? 'YES' : 'NO'
          ]);
        });
      }
      return {
        columns: [
          'table_schema',
          'table_name',
          'column_name',
          'ordinal_position',
          'data_type',
          'is_nullable'
        ],
        rows: colRows,
        commandTag: `SELECT ${colRows.length}`
      };
    } catch {
      return {
        columns: [
          'table_schema',
          'table_name',
          'column_name',
          'ordinal_position',
          'data_type',
          'is_nullable'
        ],
        rows: [],
        commandTag: 'SELECT 0'
      };
    }
  }

  if (
    upper.includes('PG_CATALOG.PG_TABLES') ||
    upper.includes('INFORMATION_SCHEMA.TABLES') ||
    upper.includes('PG_CATALOG.PG_CLASS')
  ) {
    try {
      const tablesResp = await client.get<{ tables?: TableMeta[] }>(
        `/v1/environments/${safeId(envId, 'environment_id')}/db/tables`
      );
      const tableList: TableMeta[] = Array.isArray(tablesResp?.tables)
        ? tablesResp.tables
        : [
            { name: 'patients', schema: 'public', row_count: 25 },
            { name: 'encounters', schema: 'public', row_count: 40 },
            { name: 'vital_signs', schema: 'public', row_count: 120 },
            { name: 'medications', schema: 'public', row_count: 35 },
            { name: 'conditions', schema: 'public', row_count: 30 },
            { name: 'claims', schema: 'public', row_count: 20 }
          ];
      return {
        columns: [
          'schemaname',
          'tablename',
          'table_schema',
          'table_name',
          'table_type',
          'relname',
          'relkind',
          'oid'
        ],
        rows: tableList.map((t: TableMeta, idx: number) => [
          'public',
          t.name,
          'public',
          t.name,
          'BASE TABLE',
          t.name,
          'r',
          20000 + idx
        ]),
        commandTag: `SELECT ${tableList.length}`
      };
    } catch {
      // Fall through if `/db/tables` fails
    }
  }

  if (
    upper.includes('PG_CATALOG.') ||
    upper.includes('INFORMATION_SCHEMA.')
  ) {
    return {
      columns: ['oid', 'name', 'setting'],
      rows: [],
      commandTag: 'SELECT 0'
    };
  }

  // Strip leading `public.` or `"public".` schema prefix emitted by GUIs so the isolated schema executes cleanly
  const sanitizedSql = trimmed.replace(/\b"?public"?\s*\.\s*/gi, '');

  // Forward actual SQL query to `/v1/environments/{id}/db/query`
  const apiRes = await client.post<Record<string, unknown>>(
    `/v1/environments/${safeId(envId, 'environment_id')}/db/query`,
    {
      sql: sanitizedSql,
      addon: 'postgres',
      actor_type: 'human_user'
    }
  );

  return normalizeApiQueryResult(apiRes);
}

/**
 * Checks whether a local TCP port is free to bind on 127.0.0.1.
 */
export async function isPortAvailable(
  port: number,
  host = '127.0.0.1'
): Promise<boolean> {
  return new Promise((resolve) => {
    const tester = net.createServer();
    tester.once('error', () => resolve(false));
    tester.once('listening', () => {
      tester.close(() => resolve(true));
    });
    tester.listen(port, host);
  });
}

const ALLOWED_PROXY_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
export const MAX_PG_PACKET_BYTES = 16 * 1024 * 1024; // 16 MB ceiling per PostgreSQL frame/buffer

/**
 * Starts a local TCP PostgreSQL v3 wire-protocol server on `127.0.0.1:<port>`.
 */
export async function startPgWireProxy(
  options: PgProxyOptions
): Promise<PgProxyHandle> {
  const host = (options.host ?? '127.0.0.1').trim();
  if (!ALLOWED_PROXY_HOSTS.has(host.toLowerCase())) {
    throw new Error(
      `Security error: PostgreSQL wire proxy may only bind to loopback addresses (127.0.0.1, localhost, ::1), got "${host}".`
    );
  }
  const client = options.client ?? api;
  const databaseName =
    options.database ?? `clinic_${options.envId.replace(/-/g, '_').slice(0, 12)}`;

  const server = net.createServer((socket) => {
    let startupCompleted = false;
    let buffer = Buffer.alloc(0);
    let boundStatementSql = '';

    socket.on('error', (err) => {
      options.onError?.(err);
    });

    const processBuffer = async (): Promise<void> => {
      while (buffer.length > 0) {
        if (!startupCompleted) {
          if (buffer.length < 8) return;
          const packetLen = buffer.readInt32BE(0);
          if (packetLen < 8 || packetLen > 65536) {
            socket.destroy();
            return;
          }
          if (buffer.length < packetLen) return;

          const code = buffer.readInt32BE(4);
          buffer = buffer.subarray(packetLen);

          // SSLRequest (80877103) or GSSENCRequest (80877104) -> respond 'N' (no SSL needed on loopback)
          if (code === 80877103 || code === 80877104) {
            socket.write(Buffer.from('N', 'ascii'));
            continue;
          }

          // CancelRequest (80877102) -> close socket
          if (code === 80877102) {
            socket.end();
            return;
          }

          // Protocol v3.0 StartupMessage (196608 = 0x00030000)
          startupCompleted = true;
          const handshake = Buffer.concat([
            buildAuthenticationOk(),
            buildParameterStatus(
              'server_version',
              '16.4 (Hebrah Isolated Clinic Runtime)'
            ),
            buildParameterStatus('server_encoding', 'UTF8'),
            buildParameterStatus('client_encoding', 'UTF8'),
            buildParameterStatus('DateStyle', 'ISO, MDY'),
            buildParameterStatus('integer_datetimes', 'on'),
            buildParameterStatus('IntervalStyle', 'postgres'),
            buildParameterStatus('is_superuser', 'off'),
            buildParameterStatus('session_authorization', 'hebrah_readonly'),
            buildParameterStatus('standard_conforming_strings', 'on'),
            buildParameterStatus('TimeZone', 'UTC'),
            buildParameterStatus('application_name', 'hebrah-db-proxy'),
            buildBackendKeyData(process.pid, 0x48425248),
            buildReadyForQuery('I')
          ]);
          socket.write(handshake);
          continue;
        }

        // Standard v3 frontend message: 1-byte type + 4-byte length
        if (buffer.length < 5) return;
        const msgType = String.fromCharCode(buffer[0]!);
        const msgLen = buffer.readInt32BE(1);
        if (msgLen < 4 || msgLen > MAX_PG_PACKET_BYTES) {
          socket.destroy();
          return;
        }
        if (buffer.length < 1 + msgLen) return;

        const payload = buffer.subarray(5, 1 + msgLen);
        buffer = buffer.subarray(1 + msgLen);

        if (msgType === 'X') {
          socket.end();
          return;
        }

        if (msgType === 'Q') {
          const rawQuery = payload.toString('utf8').replace(/\0+$/, '').trim();
          if (!rawQuery) {
            socket.write(
              Buffer.concat([buildEmptyQueryResponse(), buildReadyForQuery('I')])
            );
            continue;
          }

          const statements = rawQuery
            .split(/;(?=(?:[^']*'[^']*')*[^']*$)/)
            .map((s) => s.trim())
            .filter(Boolean);

          for (const stmt of statements) {
            const started = Date.now();
            try {
              const result = await executeSqlStatement(
                stmt,
                options.envId,
                databaseName,
                client
              );
              const durationMs = Date.now() - started;
              options.onQuery?.(stmt, result.rows.length, durationMs);

              const packets: Buffer[] = [];
              if (result.columns.length > 0) {
                packets.push(buildRowDescription(result.columns));
                for (const row of result.rows) {
                  packets.push(buildDataRow(row));
                }
              }
              packets.push(buildCommandComplete(result.commandTag));
              socket.write(Buffer.concat(packets));
            } catch (err) {
              const message =
                err instanceof Error ? err.message : 'Query execution failed';
              socket.write(buildErrorResponse(message));
            }
          }
          socket.write(buildReadyForQuery('I'));
          continue;
        }

        if (msgType === 'P') {
          const firstNull = payload.indexOf(0);
          if (firstNull !== -1) {
            const secondNull = payload.indexOf(0, firstNull + 1);
            if (secondNull !== -1) {
              boundStatementSql = payload
                .subarray(firstNull + 1, secondNull)
                .toString('utf8')
                .trim();
            }
          }
          socket.write(buildParseComplete());
          continue;
        }

        if (msgType === 'B') {
          socket.write(buildBindComplete());
          continue;
        }

        if (msgType === 'D') {
          const descKind =
            payload.length > 0 ? String.fromCharCode(payload[0]!) : 'P';
          if (descKind === 'S') {
            socket.write(
              Buffer.concat([buildParameterDescription(0), buildNoData()])
            );
          } else {
            socket.write(buildNoData());
          }
          continue;
        }

        if (msgType === 'E') {
          const stmt = boundStatementSql.trim();
          if (!stmt) {
            socket.write(buildEmptyQueryResponse());
            continue;
          }
          const started = Date.now();
          try {
            const result = await executeSqlStatement(
              stmt,
              options.envId,
              databaseName,
              client
            );
            const durationMs = Date.now() - started;
            options.onQuery?.(stmt, result.rows.length, durationMs);

            const packets: Buffer[] = [];
            if (result.columns.length > 0) {
              packets.push(buildRowDescription(result.columns));
              for (const row of result.rows) {
                packets.push(buildDataRow(row));
              }
            }
            packets.push(buildCommandComplete(result.commandTag));
            socket.write(Buffer.concat(packets));
          } catch (err) {
            const message =
              err instanceof Error ? err.message : 'Query execution failed';
            socket.write(buildErrorResponse(message));
          }
          continue;
        }

        if (msgType === 'C') {
          socket.write(buildCloseComplete());
          continue;
        }

        if (msgType === 'H') {
          continue;
        }

        if (msgType === 'S') {
          socket.write(buildReadyForQuery('I'));
          continue;
        }
      }
    };

    socket.on('data', (chunk: Buffer) => {
      if (buffer.length + chunk.length > MAX_PG_PACKET_BYTES) {
        socket.destroy();
        return;
      }
      buffer = Buffer.concat([buffer, chunk]);
      void processBuffer();
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port, host, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  const address = server.address();
  const actualPort =
    typeof address === 'object' && address !== null ? address.port : options.port;

  return {
    host,
    port: actualPort,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      })
  };
}
