// `hebrah login` — load existing credentials.
//
// Usage:
//   hebrah login                              (prompts for API key)
//   hebrah login --key hb_conn_*               (non-interactive)
//   hebrah login --env                         (load from $HEBRAH_API_KEY)

import { parseArgs } from 'node:util';
import { saveCredentials } from '../config/credentials.js';
import { api, ApiError } from '../api/client.js';
import { success, error, info } from '../output/format.js';

export default async function login(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? _args;
  const { values } = parseArgs({
    args: argv,
    options: {
      key: { type: 'string' },
      env: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  let apiKey = values.key as string | undefined;

  if (!apiKey && values.env) {
    apiKey = process.env.HEBRAH_API_KEY;
    if (!apiKey) {
      error('HEBRAH_API_KEY env var not set.');
      return 1;
    }
  }

  if (!apiKey && process.stdin.isTTY) {
    const { createInterface } = await import('node:readline/promises');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    apiKey = await rl.question('API key (hb_conn_*): ');
    rl.close();
  }

  if (!apiKey || !apiKey.startsWith('hb_conn_')) {
    error('API key must start with hb_conn_.');
    return 1;
  }

  api.setApiKey(apiKey);

  // Verify by calling /v1/agent/account/usage
  try {
    const usage = await api.get<{ orgId: string; tier: string }>('/v1/agent/account/usage');

    saveCredentials({
      apiKey,
      orgId: usage.orgId,
      orgName: '(unknown)',
      keyPrefix: apiKey.substring(0, 14) + '...',
      createdAt: new Date().toISOString()
    });

    success('Logged in.');
    info(`Org: ${usage.orgId}`);
    info(`Tier: ${usage.tier}`);
    return 0;
  } catch (err) {
    if (err instanceof ApiError) {
      error(`Login failed: ${err.message}`);
    } else {
      error(`Login failed: ${(err as Error).message}`);
    }
    return 2;
  }
}