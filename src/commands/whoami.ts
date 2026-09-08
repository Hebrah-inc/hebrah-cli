// `hebrah whoami` — show account info + balance.

import { loadCredentials } from '../config/credentials.js';
import { api } from '../api/client.js';
import { kv, green, dim, yellow, error } from '../output/format.js';

interface UsageResponse {
  orgId: string;
  orgName: string;
  tier: string;
  period: { start: string; end: string };
  queries: number;
  queriesDenied: number;
  egressBytes: number;
  quota: { queries: number; egressBytes: number };
  remaining: { queries: number; egressBytes: number };
  balanceCents: number;
  trial?: { expiresAt: string };
}

export default async function whoami(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const creds = loadCredentials();
  if (!creds) {
    error('Not logged in. Run `hebrah signup` or `hebrah login`.');
    return 2;
  }

  const { values } = (await import('node:util')).parseArgs({
    args: _args,
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  try {
    const usage = await api.get<UsageResponse>('/v1/agent/account/usage');

    if (options.json || values.json) {
      console.log(JSON.stringify({ ...creds, usage }, null, 2));
      return 0;
    }

    kv([
      ['Account', usage.orgName],
      ['Org ID', usage.orgId],
      ['Key prefix', creds.keyPrefix],
      ['Tier', usage.tier],
      ['Balance', `$${(usage.balanceCents / 100).toFixed(4)}`],
      ['Queries this period', `${usage.queries} / ${usage.quota.queries}`],
      ['Egress this period', `${(usage.egressBytes / 1e6).toFixed(2)} MB / ${(usage.quota.egressBytes / 1e9).toFixed(2)} GB`],
      ['Trial expires', usage.trial?.expiresAt ?? '(not on trial)']
    ]);

    return 0;
  } catch (err) {
    error((err as Error).message);
    return 4;
  }
}