// `hebrah query` — execute query through a connection.
//
// Usage:
//   hebrah query conn_uuid --sql "SELECT * FROM gl LIMIT 10"
//   hebrah query conn_uuid --file ./query.sql
//   hebrah query conn_uuid --sql "..." --max-rows 100 --json

import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { api } from '../api/client.js';
import { json, table, dim, green, yellow } from '../output/format.js';

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
  const argv = (options._argv as string[] | undefined) ?? args;
  const connId = argv.find((a) => !a.startsWith('-')) ?? args[0];
  if (!connId) {
    console.error('hebrah query: connection_id required');
    console.error('Usage: hebrah query <connection_id> --sql "SELECT ..."');
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
    sql = readFileSync(values.file as string, 'utf-8');
  }
  if (!sql) {
    console.error('hebrah query: --sql or --file required');
    return 1;
  }

  const maxRows = values['max-rows'] ? parseInt(values['max-rows'] as string, 10) : undefined;

  try {
    const result = await api.post<QueryResponse>(`/v1/connections/${connId}/query`, {
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
    console.error((err as Error).message);
    return 4;
  }
}