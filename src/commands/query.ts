// `hebrah query` — execute query through a connection.
//
// Usage:
//   hebrah query conn_uuid --sql "SELECT * FROM gl LIMIT 10"
//   hebrah query conn_uuid --file ./query.sql
//   hebrah query conn_uuid --sql "..." --max-rows 100 --json

import { parseArgs } from 'node:util';
import { readFileSync, statSync } from 'node:fs';
import { api, safeId } from '../api/client.js';
import { json, table, dim, green, yellow, error } from '../output/format.js';
import { getArgv } from '../util/args.js';

const MAX_SQL_FILE_BYTES = 1_048_576; // 1 MB

interface QueryResponse {
  rows: Array<Record<string, unknown>>;
  rowCount: number;
  auditEventId: string;
  bytesEgressed: number;
  cost: { queries: number; egressBytes: number; totalCents: number };
  scopeApplied: string;
  sqlExecuted: string;
}

export default async function query(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const connId = argv.find((a) => !a.startsWith('-')) ?? args[0];
  if (!connId) {
    error('hebrah query: connection_id required');
    error('Usage: hebrah query <connection_id> --sql "SELECT ..."');
    return 1;
  }

  // Re-parse the argv with the positional removed so parseArgs (with
  // allowPositionals: false) doesn't reject it.
  const flagOnly = argv.filter((a) => a !== connId);
  const { values } = parseArgs({
    args: flagOnly,
    options: {
      sql: { type: 'string' },
      file: { type: 'string' },
      'max-rows': { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  let sql: string | undefined = values.sql as string | undefined;
  if (!sql && values.file) {
    try {
      const filePath = String(values.file);
      const st = statSync(filePath);
      if (!st.isFile()) {
        error(`hebrah query: --file must point to a regular file (${filePath})`);
        return 1;
      }
      if (st.size > MAX_SQL_FILE_BYTES) {
        error(`hebrah query: SQL file exceeds maximum size of 1 MB (${st.size} bytes)`);
        return 1;
      }
      sql = readFileSync(filePath, 'utf-8');
    } catch (err) {
      error(`hebrah query: failed to read --file: ${(err as Error).message}`);
      return 1;
    }
  }
  if (!sql || !sql.trim()) {
    error('hebrah query: --sql or --file required');
    return 1;
  }

  let maxRows: number | undefined;
  if (values['max-rows'] !== undefined) {
    maxRows = Number.parseInt(String(values['max-rows']), 10);
    if (!Number.isFinite(maxRows) || maxRows < 1 || maxRows > 10_000) {
      error('hebrah query: --max-rows must be an integer between 1 and 10000');
      return 1;
    }
  }

  try {
    const result = await api.post<QueryResponse>(`/v1/connections/${safeId(connId, 'connection_id')}/query`, {
      sql,
      maxRows
    });

    if (values.json) {
      json(result);
      return 0;
    }

    // Render rows as a table
    if (result.rows.length > 0) {
      const headers = Object.keys(result.rows[0]);
      const rows = result.rows.map((r) => headers.map((h) => String(r[h] ?? '')));
      table(headers, rows);
    } else {
      console.log(dim('(no rows)'));
    }

    console.log();
    console.log(dim(`${result.rowCount} rows · ${result.bytesEgressed} bytes egressed · audit event ${result.auditEventId}`));
    console.log(dim(`Scope applied: ${result.scopeApplied}`));
    console.log(dim(`Cost: ${result.cost.totalCents === 0 ? green('free (within trial)') : yellow(`$${(result.cost.totalCents / 100).toFixed(4)}`)}`));

    return 0;
  } catch (err) {
    error((err as Error).message);
    return 4;
  }
}