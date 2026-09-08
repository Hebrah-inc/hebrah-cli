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
  const target = argv.find((a) => !a.startsWith('-')) ?? args[0];
  if (!target) {
    error('hebrah connect: target required');
    error('Usage: hebrah connect <target> --scopes <scope1,scope2,...> [--ttl 3600] [--tier container|vm]');
    return 1;
  }

  const flagOnly = argv.filter((a) => a !== target);
  const { values } = parseArgs({
    args: flagOnly,
    options: {
      scopes: { type: 'string' },
      ttl: { type: 'string', default: '3600' },
      tier: { type: 'string', default: 'container' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  if (!values.scopes) {
    error('--scopes required (comma-separated)');
    error('Run `hebrah inspect <target>` to see valid scopes.');
    return 1;
  }

  try {
    const result = await api.post<ConnectionResponse>('/v1/connections', {
      target,
      scopes: (values.scopes as string).split(',').map((s) => s.trim()),
      ttl: parseInt(values.ttl as string, 10),
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