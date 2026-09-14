// `hebrah login` — authenticate CLI via browser loopback, RFC 8628 device flow, or API key.
//
// Usage:
//   hebrah login                              (opens browser authorization)
//   hebrah login --headless                   (RFC 8628 device authorization for remote/SSH)
//   hebrah login --manual                     (prompts for API key in terminal)
//   hebrah login --key hb_conn_*              (non-interactive)
//   hebrah login --env                        (load from $HEBRAH_API_KEY)

import { parseArgs } from 'node:util';
import { hostname } from 'node:os';
import { saveCredentials } from '../config/credentials.js';
import { api, ApiError } from '../api/client.js';
import { success, error, info, bold, dim, cyan } from '../output/format.js';
import { startLoopbackAuth } from '../util/loopback.js';
import { openBrowser } from '../util/browser.js';

interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

interface DeviceTokenResponse {
  apiKey: string;
  keyPrefix: string;
  orgId: string;
  orgName: string;
  token_type: string;
}

function getAppUrl(): string {
  if (process.env.HEBRAH_APP_URL) {
    return process.env.HEBRAH_APP_URL.replace(/\/$/, '');
  }
  const apiUrl = process.env.HEBRAH_API_URL ?? '';
  if (apiUrl.includes('localhost') || apiUrl.includes('127.0.0.1')) {
    return 'http://localhost:3000';
  }
  return 'https://app.hebrah.com';
}

async function loginHeadlessDeviceFlow(timeoutMs: number): Promise<{
  apiKey: string;
  orgId: string;
  orgName: string;
}> {
  const clientHost = hostname();
  const codeResp = await api.post<DeviceCodeResponse>('/v1/auth/device/code', {
    client_id: 'cli',
    host: clientHost
  });

  console.log();
  info('Device authorization initiated for remote/headless environment.');
  console.log();
  console.log('  Open this link in any browser on any device:');
  console.log(`    ${bold(codeResp.verification_uri_complete)}`);
  console.log();
  console.log(`  Or visit ${codeResp.verification_uri} and enter code:`);
  console.log(`    ${bold(cyan(codeResp.user_code))}`);
  console.log();
  console.log(dim('Waiting for authorization in browser (press Ctrl+C to cancel)...'));

  const pollInterval = (codeResp.interval || 3) * 1000;
  const deadline = Date.now() + Math.min(timeoutMs, (codeResp.expires_in || 900) * 1000);

  let cancelled = false;
  const onSigint = () => {
    cancelled = true;
    console.log('\nLogin cancelled.');
    process.exit(130);
  };
  process.once('SIGINT', onSigint);

  try {
    while (Date.now() < deadline && !cancelled) {
      await new Promise((r) => setTimeout(r, pollInterval));
      if (cancelled) break;

      try {
        const tokenResp = await api.post<DeviceTokenResponse>('/v1/auth/device/token', {
          device_code: codeResp.device_code
        });
        if (tokenResp && tokenResp.apiKey) {
          return {
            apiKey: tokenResp.apiKey,
            orgId: tokenResp.orgId,
            orgName: tokenResp.orgName
          };
        }
      } catch (err) {
        if (err instanceof ApiError) {
          const detail = (err.body as { detail?: { error?: string } })?.detail;
          const errorCode = detail?.error;
          if (errorCode === 'authorization_pending' || err.statusCode === 428) {
            // Still waiting for user, continue polling
            continue;
          }
          if (errorCode === 'access_denied') {
            throw new Error('Authorization was denied by the user.');
          }
          if (errorCode === 'expired_token') {
            throw new Error('Device authorization code expired.');
          }
          throw err;
        }
        throw err;
      }
    }
    throw new Error('Device authorization timed out.');
  } finally {
    process.removeListener('SIGINT', onSigint);
  }
}

export default async function login(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? _args;
  const { values } = parseArgs({
    args: argv,
    options: {
      key: { type: 'string' },
      env: { type: 'boolean', default: false },
      manual: { type: 'boolean', default: false },
      headless: { type: 'boolean', default: false },
      timeout: { type: 'string' }
    },
    allowPositionals: false
  });

  let apiKey = values.key as string | undefined;
  let orgNameFromAuth: string | undefined;
  let orgIdFromAuth: string | undefined;
  const timeoutMs = values.timeout ? parseInt(values.timeout as string, 10) : 120_000;

  // 1. Direct --key flag
  if (apiKey) {
    // handled below
  }
  // 2. Direct --env flag
  else if (values.env) {
    apiKey = process.env.HEBRAH_API_KEY;
    if (!apiKey) {
      error('HEBRAH_API_KEY environment variable is not set.');
      return 1;
    }
  }
  // 3. Direct --manual prompt
  else if (values.manual && process.stdin.isTTY) {
    const { createInterface } = await import('node:readline/promises');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    apiKey = await rl.question('API key (hb_conn_*): ');
    rl.close();
  }
  // 4. Remote --headless Device Authorization (RFC 8628)
  else if (values.headless) {
    try {
      const result = await loginHeadlessDeviceFlow(timeoutMs);
      apiKey = result.apiKey;
      orgIdFromAuth = result.orgId;
      orgNameFromAuth = result.orgName;
    } catch (err) {
      error((err as Error).message);
      info('Run `hebrah login --headless` to try again, or `hebrah login --manual` to paste a key.');
      return 1;
    }
  }
  // 5. Default: Local Desktop Browser Loopback Authorization
  else {
    const appUrl = getAppUrl();
    const clientHost = hostname();

    let loopback;
    try {
      loopback = await startLoopbackAuth();
    } catch (err) {
      error(`Failed to start local authorization listener: ${(err as Error).message}`);
      info('You can log in using `hebrah login --headless` or `hebrah login --manual` instead.');
      return 1;
    }

    const authUrl = `${appUrl}/cli/authorize?port=${loopback.port}&state=${loopback.state}&client=cli&host=${encodeURIComponent(clientHost)}`;

    console.log();
    info('Opening your browser to authorize Hebrah CLI:');
    console.log(`  ${bold(authUrl)}`);
    console.log();
    console.log(dim('Waiting for browser authorization (press Ctrl+C to cancel)...'));

    // Handle Ctrl+C gracefully
    const onSigint = () => {
      loopback.close();
      console.log('\nLogin cancelled.');
      process.exit(130);
    };
    process.once('SIGINT', onSigint);

    const opened = await openBrowser(authUrl);
    if (!opened) {
      info('Could not automatically launch browser.');
      info('Open the link above manually, or run `hebrah login --headless` for remote device flow.');
    }

    try {
      const result = await loopback.waitForCallback(timeoutMs);
      apiKey = result.apiKey;
      orgIdFromAuth = result.orgId;
      orgNameFromAuth = result.orgName;
    } catch (err) {
      error((err as Error).message);
      info('Run `hebrah login` to try again, or `hebrah login --headless` for device flow.');
      return 1;
    } finally {
      process.removeListener('SIGINT', onSigint);
    }
  }

  if (!apiKey || !apiKey.startsWith('hb_conn_')) {
    error('API key must start with hb_conn_.');
    return 1;
  }

  api.setApiKey(apiKey);

  // Verify key against the agent API
  try {
    const usage = await api.get<{ orgId: string; tier: string }>('/v1/agent/account/usage');

    saveCredentials({
      apiKey,
      orgId: orgIdFromAuth || usage.orgId,
      orgName: orgNameFromAuth || '(workspace)',
      keyPrefix: apiKey.substring(0, 14) + '...',
      createdAt: new Date().toISOString()
    });

    console.log();
    success(`Logged in${orgNameFromAuth ? ` to ${orgNameFromAuth}` : ''}.`);
    info(`Org ID: ${orgIdFromAuth || usage.orgId}`);
    info(`Tier:   ${usage.tier}`);
    info('Credentials saved to ~/.hebrah/credentials (mode 0600).');
    return 0;
  } catch (err) {
    if (err instanceof ApiError) {
      error(`Login validation failed: ${err.message}`);
    } else {
      error(`Login validation failed: ${(err as Error).message}`);
    }
    return 2;
  }
}
