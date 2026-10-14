// `hebrah login` — authenticate CLI via browser loopback, RFC 8628 device flow, or API key.
//
// Usage:
//   hebrah login                              (opens browser authorization)
//   hebrah login --env-id <id>                (opens browser auth & connects agent to clinic environment)
//   hebrah login --headless                   (RFC 8628 device authorization for remote/SSH)
//   hebrah login --manual                     (prompts for API key in terminal)
//   hebrah login --key hb_conn_*|hb_pat_*     (non-interactive)
//   hebrah login --env                        (load from $HEBRAH_API_KEY)
//   hebrah login --app-url <url> --api-url <url> (explicit staging/custom environment)

import { parseArgs } from 'node:util';
import { hostname } from 'node:os';
import {
  saveCredentials,
  loadCredentials,
  isValidApiKeyFormat,
  maskApiKey
} from '../config/credentials.js';
import {
  api,
  ApiError,
  inferApiUrlFromAppUrl,
  safeId,
  validateApiBaseUrl
} from '../api/client.js';
import { success, error, info, bold, dim, cyan, kv } from '../output/format.js';
import { startLoopbackAuth } from '../util/loopback.js';
import { openBrowser } from '../util/browser.js';
import type { EnvironmentDetail } from './env.js';

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

function resolveAppUrl(explicitAppUrl?: string, explicitApiUrl?: string): string {
  if (explicitAppUrl) {
    return explicitAppUrl.replace(/\/$/, '');
  }
  if (process.env.HEBRAH_APP_URL) {
    return process.env.HEBRAH_APP_URL.replace(/\/$/, '');
  }
  const savedAppUrl = loadCredentials()?.appUrl;
  if (savedAppUrl) {
    return savedAppUrl.replace(/\/$/, '');
  }
  const apiUrl = explicitApiUrl ?? process.env.HEBRAH_API_URL ?? loadCredentials()?.apiUrl ?? '';
  if (apiUrl.includes('localhost') || apiUrl.includes('127.0.0.1')) {
    return 'http://localhost:3000';
  }
  if (apiUrl.includes('-api-')) {
    return apiUrl.replace('-api-', '-app-').replace(/\/$/, '');
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
      timeout: { type: 'string' },
      'app-url': { type: 'string' },
      'api-url': { type: 'string' },
      'env-id': { type: 'string' },
      'agent-name': { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  let apiKey = values.key as string | undefined;
  let orgNameFromAuth: string | undefined;
  let orgIdFromAuth: string | undefined;
  const timeoutMs = values.timeout ? parseInt(values.timeout as string, 10) : 120_000;

  const flagAppUrl = values['app-url'] as string | undefined;
  let flagApiUrl = values['api-url'] as string | undefined;
  let targetEnvId = (values['env-id'] as string | undefined) ?? process.env.HEBRAH_ENV_ID;
  const agentName = (values['agent-name'] as string | undefined) || `cli-agent-${hostname()}`;

  if (!flagApiUrl && flagAppUrl) {
    flagApiUrl = inferApiUrlFromAppUrl(flagAppUrl);
  }
  const appUrl = resolveAppUrl(flagAppUrl, flagApiUrl);
  if (!flagApiUrl && appUrl) {
    const inferred = inferApiUrlFromAppUrl(appUrl);
    if (inferred && !process.env.HEBRAH_API_URL) {
      flagApiUrl = inferred;
    }
  }

  if (flagApiUrl) {
    try {
      flagApiUrl = validateApiBaseUrl(flagApiUrl);
      api.setBaseUrl(flagApiUrl);
    } catch (err) {
      error((err as Error).message);
      return 1;
    }
  }

  // 1. Direct --key flag
  if (apiKey) {
    apiKey = apiKey.trim();
  }
  // 2. Direct --env flag
  else if (values.env) {
    apiKey = process.env.HEBRAH_API_KEY?.trim();
    if (!apiKey) {
      error('HEBRAH_API_KEY environment variable is not set.');
      return 1;
    }
  }
  // 3. Direct --manual prompt
  else if (values.manual && process.stdin.isTTY) {
    const { createInterface } = await import('node:readline/promises');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    apiKey = (await rl.question('API key (hb_conn_* or hb_pat_*): ')).trim();
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
    const clientHost = hostname();

    let loopback;
    try {
      loopback = await startLoopbackAuth();
    } catch (err) {
      error(`Failed to start local authorization listener: ${(err as Error).message}`);
      info('You can log in using `hebrah login --headless` or `hebrah login --manual` instead.');
      return 1;
    }

    const queryParams = new URLSearchParams({
      port: String(loopback.port),
      state: loopback.state,
      client: 'cli',
      host: clientHost
    });
    if (targetEnvId) {
      queryParams.set('env_id', targetEnvId);
    }

    const authUrl = `${appUrl}/cli/authorize?${queryParams.toString()}`;

    console.log();
    info('Opening your browser to authorize Hebrah CLI:');
    console.log(`  ${bold(authUrl)}`);
    console.log();
    console.log(dim('Waiting for browser authorization (press Ctrl+C to cancel)...'));

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
      if (result.apiUrl) {
        try {
          flagApiUrl = validateApiBaseUrl(result.apiUrl);
          api.setBaseUrl(flagApiUrl);
        } catch {
          // ignore invalid callback apiUrl; keep validated base URL
        }
      }
      if (result.envId && !targetEnvId) {
        targetEnvId = result.envId;
      }
    } catch (err) {
      error((err as Error).message);
      info('Run `hebrah login` to try again, or `hebrah login --headless` for device flow.');
      return 1;
    } finally {
      process.removeListener('SIGINT', onSigint);
    }
  }

  if (!apiKey || !isValidApiKeyFormat(apiKey)) {
    error('API key must start with hb_conn_, hb_pat_, hb_live_, or hb_test_ (minimum 16 characters).');
    return 1;
  }

  api.setApiKey(apiKey);
  const resolvedApiUrl = api.getBaseUrl();

  // Verify key against the agent API (with fallback to /v1/environments for scoped tokens)
  try {
    let resolvedOrgId = orgIdFromAuth || '';
    let resolvedOrgName = orgNameFromAuth || '';
    let resolvedTier = 'active';

    try {
      const usage = await api.get<{ orgId: string; orgName?: string; tier: string }>(
        '/v1/agent/account/usage'
      );
      resolvedOrgId = resolvedOrgId || usage.orgId;
      resolvedOrgName = resolvedOrgName || usage.orgName || '(workspace)';
      resolvedTier = usage.tier || 'active';
    } catch (usageErr) {
      // Fallback: verify token via /v1/environments
      const envsRes = await api.get<Array<{ org_id: string }> | { environments: Array<{ org_id: string }> }>(
        '/v1/environments'
      );
      const envList = Array.isArray(envsRes) ? envsRes : (envsRes.environments ?? []);
      if (envList.length > 0 && envList[0].org_id) {
        resolvedOrgId = resolvedOrgId || envList[0].org_id;
      }
      if (!resolvedOrgId) {
        resolvedOrgId = 'org-verified';
      }
      resolvedOrgName = resolvedOrgName || '(workspace)';
      void usageErr;
    }

    saveCredentials({
      apiKey,
      orgId: resolvedOrgId,
      orgName: resolvedOrgName,
      keyPrefix: maskApiKey(apiKey),
      createdAt: new Date().toISOString(),
      apiUrl: resolvedApiUrl,
      appUrl,
      defaultEnvId: targetEnvId
    });

    let connectedEnv: EnvironmentDetail | null = null;
    if (targetEnvId) {
      try {
        connectedEnv = await api.post<EnvironmentDetail>(
          `/v1/environments/${safeId(targetEnvId, 'environment_id')}/agents/connect`,
          {
            agent_name: agentName,
            client: 'hebrah-cli'
          }
        );
      } catch {
        // Fallback to GET /v1/environments/{id} if server doesn't have /agents/connect yet
        try {
          connectedEnv = await api.get<EnvironmentDetail>(
            `/v1/environments/${safeId(targetEnvId, 'environment_id')}`
          );
        } catch (envErr) {
          info(`Note: Could not auto-attach to environment ${targetEnvId}: ${(envErr as Error).message}`);
        }
      }
    }

    if (values.json) {
      console.log(
        JSON.stringify(
          {
            ok: true,
            orgId: resolvedOrgId,
            orgName: resolvedOrgName,
            keyPrefix: maskApiKey(apiKey),
            apiUrl: resolvedApiUrl,
            appUrl,
            defaultEnvId: targetEnvId ?? null,
            environment: connectedEnv
          },
          null,
          2
        )
      );
      return 0;
    }

    console.log();
    success(`Logged in${resolvedOrgName ? ` to ${resolvedOrgName}` : ''}.`);
    info(`Org ID:       ${resolvedOrgId}`);
    info(`Tier:         ${resolvedTier}`);
    info(`API Endpoint: ${resolvedApiUrl}`);
    info('Credentials saved to ~/.hebrah/credentials (mode 0600).');

    if (connectedEnv) {
      console.log();
      success(`Connected agent "${agentName}" to clinic environment: ${bold(connectedEnv.name)} (${connectedEnv.id})`);
      kv([
        ['Environment ID', connectedEnv.id],
        ['Clinic Type', connectedEnv.clinic_type],
        ['Status', connectedEnv.status],
        ['Attached DBs', (connectedEnv.addons ?? []).join(', ') || 'none'],
        ['FHIR R4 Endpoint', connectedEnv.endpoints?.fhir ?? 'n/a'],
        ['HL7 v2 Stream', connectedEnv.endpoints?.hl7_ws ?? 'n/a']
      ]);
      console.log();
      info(`Default environment set to ${connectedEnv.id}. Run \`hebrah env status\` or \`hebrah env query "SELECT * FROM patients LIMIT 5"\`.`);
    }

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
