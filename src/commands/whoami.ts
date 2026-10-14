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

  const argv = (options._argv as string[] | undefined) ?? _args;
  const { values } = (await import('node:util')).parseArgs({
    args: argv,
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  try {
    const usage = await api.get<UsageResponse>('/v1/agent/account/usage');

    if (values.json) {
      const { apiKey: _redacted, ...safeCreds } = creds;
      console.log(
        JSON.stringify(
          {
            ...safeCreds,
            apiUrl: api.getBaseUrl(),
            usage
          },
          null,
          2
        )
      );
      return 0;
    }

    const rows: Array<[string, string]> = [
      ['Account', usage.orgName],
      ['Org ID', usage.orgId],
      ['Key prefix', creds.keyPrefix],
      ['API Endpoint', api.getBaseUrl()],
      ['Default Env', creds.defaultEnvId ?? '(none)'],
      ['Tier', usage.tier],
      ['Balance', `$${(usage.balanceCents / 100).toFixed(4)}`],
      ['Queries this period', `${usage.queries} / ${usage.quota.queries}`],
      ['Egress this period', `${(usage.egressBytes / 1e6).toFixed(2)} MB / ${(usage.quota.egressBytes / 1e9).toFixed(2)} GB`],
      ['Trial expires', usage.trial?.expiresAt ?? '(not on trial)']
    ];
    kv(rows);

    return 0;
  } catch (err) {
    error((err as Error).message);
    return 4;
  }
}