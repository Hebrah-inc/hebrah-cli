// `hebrah status <conn>` — show connection status.

import { parseArgs } from 'node:util';
import { api, safeId } from '../api/client.js';
import { json, kv, green, error } from '../output/format.js';
import { getArgv } from '../util/args.js';

interface ConnectionDetail {
  connectionId: string;
  target: string;
  scopes: string[];
  tier: string;
  ttlRemaining: number;
  ttlExpiresAt: string;
  queriesRun: number;
  bytesEgressed: number;
  auditEventCount: number;
  lastQueryAt: string | null;
  status: 'active' | 'revoked' | 'expired';
}

export default async function status(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const connId = argv.find((a) => !a.startsWith('-')) ?? args[0];
  if (!connId) {
    error('hebrah status: connection_id required');
    return 1;
  }

  const flagOnly = argv.filter((a) => a !== connId);
  const { values } = parseArgs({
    args: flagOnly,
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  try {
    const detail = await api.get<ConnectionDetail>(`/v1/connections/${safeId(connId, 'connection_id')}`);

    if (values.json) {
      json(detail);
      return 0;
    }

    kv([
      ['Connection ID', detail.connectionId],
      ['Target', detail.target],
      ['Scopes', detail.scopes.join(', ')],
      ['Tier', detail.tier],
      ['TTL', `${detail.ttlRemaining}s (expires ${detail.ttlExpiresAt})`],
      ['Queries run', String(detail.queriesRun)],
      ['Bytes egressed', String(detail.bytesEgressed)],
      ['Audit events', String(detail.auditEventCount)],
      ['Last query', detail.lastQueryAt ?? '(never)'],
      ['Status', detail.status === 'active' ? green(detail.status) : detail.status]
    ]);

    return 0;
  } catch (err) {
    error((err as Error).message);
    return 4;
  }
}