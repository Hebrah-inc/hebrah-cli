// `hebrah usage` — show metering for current period.

import { parseArgs } from 'node:util';
import { api } from '../api/client.js';
import { json, kv, dim } from '../output/format.js';

interface UsageResponse {
  period: { start: string; end: string };
  queries: number;
  queriesDenied: number;
  egressBytes: number;
  quota: { queries: number; egressBytes: number };
  remaining: { queries: number; egressBytes: number };
  balanceCents: number;
}

export default async function usage(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? _args;
  const { values } = parseArgs({
    args: argv,
    options: {
      period: { type: 'string', default: 'month' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  try {
    const usage = await api.get<UsageResponse>('/v1/agent/account/usage', {
      period: values.period as string
    });

    if (values.json) {
      json(usage);
      return 0;
    }

    console.log(dim(`Period: ${usage.period.start} → ${usage.period.end}`));
    console.log();
    kv([
      ['Queries', `${usage.queries} / ${usage.quota.queries} (${usage.remaining.queries} remaining)`],
      ['Queries denied', `${usage.queriesDenied}`],
      ['Egress', `${(usage.egressBytes / 1e6).toFixed(2)} MB / ${(usage.quota.egressBytes / 1e9).toFixed(2)} GB (${(usage.remaining.egressBytes / 1e6).toFixed(2)} MB remaining)`],
      ['Balance', `$${(usage.balanceCents / 100).toFixed(4)}`]
    ]);

    return 0;
  } catch (err) {
    console.error((err as Error).message);
    return 4;
  }
}