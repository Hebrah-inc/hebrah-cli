// `hebrah connect` — open a scoped connection.
//
// Usage:
//   hebrah connect <target> --scopes <scope1,scope2,...> [--ttl 3600] [--tier container|vm]

import { parseArgs } from 'node:util';
import { api } from '../api/client.js';
import { json, success, info, error, kv } from '../output/format.js';
import { getArgv } from '../util/args.js';

interface ConnectionResponse {
  connectionId: string;
  target: string;
  scopes: string[];
  tier: string;
  ttl: number;
  ttlExpiresAt: string;
  auditGenesisHash: string;
}

export default async function connect(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      scopes: { type: 'string' },
      ttl: { type: 'string', default: '3600' },
      tier: { type: 'string', default: 'container' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const target = positionals[0] ?? args[0];
  if (!target) {
    error('hebrah connect: target required');
    error('Usage: hebrah connect <target> --scopes <scope1,scope2,...> [--ttl 3600] [--tier container|vm]');
    return 1;
  }

  if (!values.scopes) {
    error('--scopes required (comma-separated)');
    error('Run `hebrah inspect <target>` to see valid scopes.');
    return 1;
  }

  const ttl = Number.parseInt(String(values.ttl ?? '3600'), 10);
  if (!Number.isFinite(ttl) || ttl < 60 || ttl > 604_800) {
    error('Invalid --ttl: must be an integer between 60 and 604800 seconds');
    return 1;
  }

  try {
    const result = await api.post<ConnectionResponse>('/v1/connections', {
      target,
      scopes: (values.scopes as string).split(',').map((s) => s.trim()),
      ttl,
      tier: values.tier
    });

    if (values.json) {
      json(result);
      return 0;
    }

    success(`Connection opened: ${result.connectionId}`);
    console.log();
    kv([
      ['Target', result.target],
      ['Scopes', result.scopes.join(', ')],
      ['Tier', result.tier],
      ['TTL', `${result.ttl}s (expires ${result.ttlExpiresAt})`],
      ['Genesis hash', result.auditGenesisHash]
    ]);
    console.log();
    info(`Next: hebrah query ${result.connectionId} --sql "SELECT ..."`);

    return 0;
  } catch (err) {
    error((err as Error).message);
    return 4;
  }
}