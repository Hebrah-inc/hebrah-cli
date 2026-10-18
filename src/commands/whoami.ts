// `hebrah whoami` — show account info + balance.

import { parseArgs } from 'node:util';
import { loadCredentials, maskApiKey } from '../config/credentials.js';
import { api } from '../api/client.js';
import { kv, json, error } from '../output/format.js';

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
  const envKey = process.env.HEBRAH_API_KEY?.trim();
  if (!creds && !envKey) {
    error('Not logged in. Run `hebrah signup` or `hebrah login`.');
    return 2;
  }

  const argv = (options._argv as string[] | undefined) ?? _args;
  const { values } = parseArgs({
    args: argv,
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  const keyPrefix = creds?.keyPrefix ?? (envKey ? maskApiKey(envKey) : '');
  const defaultEnvId = creds?.defaultEnvId ?? process.env.HEBRAH_ENV_ID;

  try {
    const usage = await api.get<UsageResponse>('/v1/agent/account/usage');

    if (values.json) {
      const { apiKey: _redacted, ...safeCreds } = creds ?? {};
      void _redacted;
      json({
        ...safeCreds,
        keyPrefix,
        defaultEnvId,
        apiUrl: api.getBaseUrl(),
        usage
      });
      return 0;
    }

    const rows: Array<[string, string]> = [
      ['Account', usage.orgName],
      ['Org ID', usage.orgId],
      ['Key prefix', keyPrefix],
      ['API Endpoint', api.getBaseUrl()],
      ['Default Env', defaultEnvId ?? '(none)'],
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