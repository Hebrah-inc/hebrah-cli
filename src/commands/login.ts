// `hebrah login` — authenticate CLI via browser loopback, RFC 8628 device flow, or API key.
//
// Usage:
//   hebrah login                              (opens browser authorization)
//   hebrah login --env-id <id>                (opens browser auth & connects agent to clinic environment)
//   hebrah login --headless                   (RFC 8628 device authorization for remote/SSH)
//   hebrah login --key-stdin                  (reads API key from piped stdin — zero argv/history exposure)
//   hebrah login --manual                     (prompts for API key in terminal with hidden echo)
//   hebrah login --key [hb_conn_*|hb_pat_*]   (non-interactive flag or hidden prompt if value omitted)
//   hebrah login --env                        (load from $HEBRAH_API_KEY)
//   hebrah login --app-url <url> --api-url <url> (explicit staging/custom environment)

import { parseArgs } from 'node:util';
import { hostname } from 'node:os';
import { randomBytes } from 'node:crypto';
import { Writable } from 'node:stream';
import {
  saveCredentials,
  isValidApiKeyFormat,
  maskApiKey
} from '../config/credentials.js';
import {
  api,
  ApiError,
  safeId,
  validateApiBaseUrl
} from '../api/client.js';
import { success, error, info, bold, dim, cyan, kv, json, sanitizeTerminalText } from '../output/format.js';
import { startLoopbackAuth, type LoopbackAuthResult, type LoopbackAuthServer } from '../util/loopback.js';
import { openBrowser, validateBrowserUrl } from '../util/browser.js';
import { applyAuthUrlFlags, getArgv, resolveAppUrl } from '../util/args.js';
import type { EnvironmentDetail } from './env.js';

export { resolveAppUrl };

const MAX_STDIN_KEY_BYTES = 4096;

/**
 * Scrubs an inline API key from `process.argv` and resets `process.title`
 * to minimize exposure in `ps aux` / process table inspection.
 */
export function scrubProcessArgvSecret(secret: string): void {
  if (!secret) return;
  for (let i = 0; i < process.argv.length; i++) {
    const arg = process.argv[i];
    if (!arg) continue;
    if (arg === secret) {
      process.argv[i] = '[REDACTED]';
    } else if (arg.includes(secret)) {
      process.argv[i] = arg.split(secret).join('[REDACTED]');
    }
  }
  try {
    process.title = 'hebrah';
  } catch {
    // Ignore on platforms where process.title is read-only
  }
}

/**
 * Reads an API key from a piped non-TTY stream (e.g. `echo "$KEY" | hebrah login --key-stdin`)
 * with a strict 4 KB upper bound to prevent memory exhaustion.
 */
export async function readKeyFromStdin(
  stream: NodeJS.ReadableStream = process.stdin,
  maxBytes = MAX_STDIN_KEY_BYTES
): Promise<string> {
  if ((stream as { isTTY?: boolean }).isTTY) {
    throw new Error(
      '--key-stdin requires piping an API key via standard input (e.g. `echo "$HEBRAH_API_KEY" | hebrah login --key-stdin`).'
    );
  }

  return new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let settled = false;

    const cleanup = () => {
      stream.removeListener('data', onData);
      stream.removeListener('end', onEnd);
      stream.removeListener('error', onError);
    };

    const onData = (chunk: Buffer | string) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf-8');
      totalBytes += buf.length;
      if (totalBytes > maxBytes) {
        settled = true;
        cleanup();
        reject(
          new Error(
            `Standard input exceeded maximum allowed API key length (${maxBytes} bytes).`
          )
        );
        return;
      }
      chunks.push(buf);
    };

    const onEnd = () => {
      if (settled) return;
      settled = true;
      cleanup();
      const raw = Buffer.concat(chunks).toString('utf-8');
      const firstLine = raw.split(/\r?\n/).find((line) => line.trim().length > 0) ?? '';
      resolve(firstLine.trim());
    };

    const onError = (err: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };

    stream.on('data', onData);
    stream.on('end', onEnd);
    stream.on('error', onError);
  });
}

/**
 * Prompts for an API key interactively on a TTY with terminal character echo suppressed.
 */
export async function promptHiddenApiKey(
  promptText = 'API key (hb_conn_*, hb_pat_*, hb_live_*, or hb_test_*): '
): Promise<string> {
  const { createInterface } = await import('node:readline/promises');
  process.stdout.write(promptText);
  const mutedOutput = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    }
  });
  const rl = createInterface({
    input: process.stdin,
    output: mutedOutput,
    terminal: true
  });
  try {
    const answer = await rl.question('');
    return answer.trim();
  } finally {
    rl.close();
    process.stdout.write('\n');
  }
}

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
  envId?: string | null;
  token_type: string;
}

interface PollDeviceTokenOptions {
  deviceCode: string;
  pollIntervalMs: number;
  deadlineMs: number;
  isCancelled: () => boolean;
  ignoreTransientErrors: boolean;
  timeoutMessage: string;
}

async function pollDeviceToken(opts: PollDeviceTokenOptions): Promise<LoopbackAuthResult> {
  while (Date.now() < opts.deadlineMs && !opts.isCancelled()) {
    await new Promise((r) => setTimeout(r, opts.pollIntervalMs));
    if (opts.isCancelled()) break;

    try {
      const tokenResp = await api.post<DeviceTokenResponse>('/v1/auth/device/token', {
        device_code: opts.deviceCode
      });
      if (tokenResp && tokenResp.apiKey) {
        return {
          apiKey: tokenResp.apiKey,
          orgId: tokenResp.orgId,
          orgName: tokenResp.orgName,
          envId: tokenResp.envId ?? undefined
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
      }
      if (!opts.ignoreTransientErrors) {
        throw err;
      }
    }
  }
  throw new Error(opts.timeoutMessage);
}

function pollStateTokenFromCloud(
  stateNonce: string,
  timeoutMs: number,
  isCancelled: () => boolean
): Promise<LoopbackAuthResult> {
  return pollDeviceToken({
    deviceCode: stateNonce,
    pollIntervalMs: 2000,
    deadlineMs: Date.now() + timeoutMs,
    isCancelled,
    ignoreTransientErrors: true,
    timeoutMessage: `Login timed out after ${Math.round(timeoutMs / 1000)} seconds.`
  });
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

  const safeUriComplete = validateBrowserUrl(sanitizeTerminalText(codeResp.verification_uri_complete));
  const safeUri = validateBrowserUrl(sanitizeTerminalText(codeResp.verification_uri));
  const safeUserCode = sanitizeTerminalText(codeResp.user_code);

  console.log();
  info('Device authorization initiated for remote/headless environment.');
  console.log();
  console.log('  Open this link in any browser on any device:');
  console.log(`    ${bold(safeUriComplete)}`);
  console.log();
  console.log(`  Or visit ${safeUri} and enter code:`);
  console.log(`    ${bold(cyan(safeUserCode))}`);
  console.log();
  console.log(dim('Waiting for authorization in browser (press Ctrl+C to cancel)...'));

  const rawIntervalSec = Number(codeResp.interval);
  const pollInterval = Math.min(
    30_000,
    Math.max(1_000, (Number.isFinite(rawIntervalSec) && rawIntervalSec > 0 ? rawIntervalSec : 3) * 1000)
  );
  const rawExpiresSec = Number(codeResp.expires_in);
  const expiresMs = Math.min(
    3_600_000,
    Math.max(5_000, (Number.isFinite(rawExpiresSec) && rawExpiresSec > 0 ? rawExpiresSec : 900) * 1000)
  );
  const deadline = Date.now() + Math.min(timeoutMs, expiresMs);

  let cancelled = false;
  const onSigint = () => {
    cancelled = true;
    console.log('\nLogin cancelled.');
    process.exit(130);
  };
  process.once('SIGINT', onSigint);

  try {
    return await pollDeviceToken({
      deviceCode: codeResp.device_code,
      pollIntervalMs: pollInterval,
      deadlineMs: deadline,
      isCancelled: () => cancelled,
      ignoreTransientErrors: false,
      timeoutMessage: 'Device authorization timed out.'
    });
  } finally {
    process.removeListener('SIGINT', onSigint);
  }
}

export default async function login(
  _args: string[],
  options: Record<string, unknown> = {}
): Promise<number> {
  const rawArgv = getArgv(options, _args);
  // Convert bare `--key` (with no value following it) into `--manual` interactive hidden prompt
  const argv = rawArgv.map((arg, idx) => {
    if (arg === '--key') {
      const next = rawArgv[idx + 1];
      if (!next || next.startsWith('-')) {
        return '--manual';
      }
    }
    return arg;
  });

  const { values } = parseArgs({
    args: argv,
    options: {
      key: { type: 'string' },
      'key-stdin': { type: 'boolean', default: false },
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
  if (apiKey) {
    scrubProcessArgvSecret(apiKey);
  }
  let orgNameFromAuth: string | undefined;
  let orgIdFromAuth: string | undefined;
  let timeoutMs = 600_000;
  if (values.timeout !== undefined) {
    const parsedTimeout = parseInt(values.timeout as string, 10);
    if (!Number.isFinite(parsedTimeout) || parsedTimeout < 1_000 || parsedTimeout > 3_600_000) {
      error('--timeout must be between 1000 and 3600000 ms.');
      return 1;
    }
    timeoutMs = parsedTimeout;
  }

  const rawEnvId = (values['env-id'] as string | undefined) ?? process.env.HEBRAH_ENV_ID;
  const agentName = sanitizeTerminalText((values['agent-name'] as string | undefined) || `cli-agent-${hostname()}`);

  let appUrl: string;
  let flagApiUrl: string | undefined;
  let targetEnvId: string | undefined;
  try {
    const resolved = applyAuthUrlFlags({
      appUrl: values['app-url'] as string | undefined,
      apiUrl: values['api-url'] as string | undefined,
      envId: rawEnvId,
      inferFromResolvedAppUrl: true
    });
    appUrl = resolved.appUrl;
    flagApiUrl = resolved.flagApiUrl;
    targetEnvId = resolved.envId;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }

  const stdinStream =
    (options._stdin as NodeJS.ReadableStream | undefined) ?? process.stdin;

  // 1. Direct --key flag
  if (apiKey) {
    apiKey = apiKey.trim();
  }
  // 2. Piped --key-stdin flag (zero argv/shell-history exposure)
  else if (values['key-stdin']) {
    try {
      apiKey = await readKeyFromStdin(stdinStream);
    } catch (err) {
      error((err as Error).message);
      return 1;
    }
  }
  // 3. Direct --env flag
  else if (values.env) {
    apiKey = process.env.HEBRAH_API_KEY?.trim();
    if (!apiKey) {
      error('HEBRAH_API_KEY environment variable is not set.');
      return 1;
    }
  }
  // 4. Direct --manual (or bare --key) prompt with hidden terminal echo
  else if (values.manual) {
    if ((stdinStream as { isTTY?: boolean }).isTTY) {
      apiKey = await promptHiddenApiKey();
    } else {
      try {
        apiKey = await readKeyFromStdin(stdinStream);
      } catch (err) {
        error((err as Error).message);
        return 1;
      }
    }
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
  // 5. Default: Browser Authorization (Cloud-Polled + Optional Loopback — Zero Localhost Redirect)
  else {
    const clientHost = hostname();

    let loopback: LoopbackAuthServer | null = null;
    try {
      loopback = await startLoopbackAuth();
    } catch {
      // Loopback port binding is optional (e.g. inside sandboxed agent containers);
      // cloud polling by `state` handles token retrieval seamlessly.
      loopback = null;
    }

    const stateNonce = loopback ? loopback.state : randomBytes(32).toString('hex');

    const queryParams = new URLSearchParams({
      state: stateNonce,
      client: 'cli',
      host: clientHost
    });
    if (loopback) {
      queryParams.set('port', String(loopback.port));
    }
    if (targetEnvId) {
      queryParams.set('env_id', targetEnvId);
    }

    const authUrl = `${appUrl}/cli/authorize?${queryParams.toString()}`;

    console.log();
    info('Opening your browser to authorize Hebrah CLI:');
    console.log(`  ${bold(authUrl)}`);
    console.log();
    console.log(dim('Waiting for browser authorization (press Ctrl+C to cancel)...'));

    let cancelled = false;
    const onSigint = () => {
      cancelled = true;
      loopback?.close();
      console.log('\nLogin cancelled.');
      process.exit(130);
    };
    process.once('SIGINT', onSigint);

    const opened = await openBrowser(authUrl);
    if (!opened) {
      info('Could not automatically launch browser.');
      info('Open the link above manually to click "Authorize CLI".');
    }

    try {
      const waiters: Array<Promise<LoopbackAuthResult>> = [
        pollStateTokenFromCloud(stateNonce, timeoutMs, () => cancelled)
      ];
      if (loopback) {
        waiters.push(loopback.waitForCallback(timeoutMs));
      }
      const result = await Promise.any(waiters);
      cancelled = true;
      loopback?.close();

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
      cancelled = true;
      loopback?.close();
      const msg = err instanceof AggregateError && err.errors.length > 0
        ? (err.errors[0] as Error).message
        : (err as Error).message;
      error(msg);
      info('Run `hebrah login` to try again, or copy the `npx @hebrah/cli login --key ...` command shown on the web page.');
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
      json({
        ok: true,
        orgId: resolvedOrgId,
        orgName: resolvedOrgName,
        keyPrefix: maskApiKey(apiKey),
        apiUrl: resolvedApiUrl,
        appUrl,
        defaultEnvId: targetEnvId ?? null,
        environment: connectedEnv
      });
      return 0;
    }

    console.log();
    success(`Logged in${resolvedOrgName ? ` to ${resolvedOrgName}` : ''}.`);
    info(`Org ID:       ${resolvedOrgId}`);
    info(`Tier:         ${resolvedTier}`);
    info(`API Endpoint: ${resolvedApiUrl}`);
    info('Credentials saved to ~/.hebrah/credentials (mode 0600).');
    info('Tip: Run `hebrah mcp install` to configure Hosted MCP at user scope for Claude Code, Cursor & IDEs.');

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
