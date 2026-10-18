// `hebrah list` — list active connections.

import { parseArgs } from 'node:util';
import { api } from '../api/client.js';
import { json, table, dim, error, formatBytes, formatDuration } from '../output/format.js';
import { getArgv } from '../util/args.js';

interface Connection {
  connectionId: string;
  target: string;
  scopes: string[];
  ttlRemaining: number;
  queriesRun: number;
  bytesEgressed: number;
  status: 'active' | 'revoked' | 'expired';
}

export default async function list(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, _args);
  const { values } = parseArgs({
    args: argv,
    options: {
      all: { type: 'boolean', default: false },
      target: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  const params: Record<string, string> = {};
  if (!values.all) params.status = 'active';
  if (values.target) params.target = values.target as string;

  try {
    const conns = await api.get<Connection[]>('/v1/connections', params);

    if (values.json) {
      json(conns);
      return 0;
    }

    if (conns.length === 0) {
      console.log(dim('(no active connections)'));
      console.log(dim('Start one: hebrah connect <target> --scopes <...>'));
      return 0;
    }

    const rows = conns.map((c) => [
      c.connectionId.substring(0, 8) + '...',
      c.target,
      c.scopes.join(', ').substring(0, 40),
      formatDuration(c.ttlRemaining),
      String(c.queriesRun),
      formatBytes(c.bytesEgressed)
    ]);

    table(['CONNECTION_ID', 'TARGET', 'SCOPES', 'TTL_REMAINING', 'QUERIES', 'BYTES'], rows);

    console.log();
    console.log(dim(`Total: ${conns.length} connection${conns.length === 1 ? '' : 's'}`));

    return 0;
  } catch (err) {
    error((err as Error).message);
    return 4;
  }
}