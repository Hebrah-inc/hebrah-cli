// `hebrah signup` — create a new agent account.
//
// Usage:
//   hebrah signup --name "agent" --email "you@company.com"
//   hebrah signup --name "agent" --headless   (no email; pure agent account)
//   hebrah signup                             (interactive prompts)
//
// Returns 0 on success (saves credentials), 1 on user error, 4 on server error.

import { parseArgs } from 'node:util';
import { api, ApiError, inferApiUrlFromAppUrl, validateApiBaseUrl } from '../api/client.js';
import { saveCredentials, maskApiKey } from '../config/credentials.js';
import { json, success, info, error, bold } from '../output/format.js';

interface SignupResponse {
  orgId: string;
  orgName: string;
  apiKey: string;
  trial: {
    credits: { queries: number; egressBytes: number };
    expiresAt?: string;
    expires_at?: string;
  };
  mcpEndpointUrl?: string;
  claimUrl?: string;
  inviteEmail?: string;
}

export default async function signup(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? _args;
  const { values } = parseArgs({
    args: argv,
    options: {
      name: { type: 'string' },
      'agent-name': { type: 'string' },
      email: { type: 'string' },
      headless: { type: 'boolean', default: false },
      'api-url': { type: 'string' },
      'app-url': { type: 'string' },
      'env-id': { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  const flagAppUrl = values['app-url'] as string | undefined;
  let flagApiUrl = values['api-url'] as string | undefined;
  if (!flagApiUrl && flagAppUrl) {
    flagApiUrl = inferApiUrlFromAppUrl(flagAppUrl);
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

  // Interactive prompts (only if TTY and no flags)
  let orgName = (values.name ?? values['agent-name']) as string | undefined;
  let inviteEmail = values.email as string | undefined;

  if (!orgName && process.stdin.isTTY && !values.headless) {
    const { createInterface } = await import('node:readline/promises');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    orgName = await rl.question('Organization name: ');
    rl.close();
  }

  if (!orgName || orgName.length < 2) {
    error('Organization name must be at least 2 characters.');
    return 1;
  }

  if (!values.headless) {
    if (!inviteEmail && process.stdin.isTTY) {
      const { createInterface } = await import('node:readline/promises');
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      inviteEmail = await rl.question('Invite email (for billing ownership): ');
      rl.close();
    }
    if (!inviteEmail || !inviteEmail.includes('@')) {
      error('A valid email is required for billing ownership. Use --headless to skip.');
      return 1;
    }
  }

  try {
    const result = await api.post<SignupResponse>('/v1/agent/account', {
      orgName,
      inviteEmail: inviteEmail ?? `${orgName.replace(/\s+/g, '-')}@agent.local`,
      headless: values.headless ?? false,
      agentName: (values['agent-name'] as string | undefined) ?? orgName
    });

    const expiresAt =
      result.trial.expiresAt ??
      result.trial.expires_at ??
      new Date(Date.now() + 14 * 86400000).toISOString();

    const resolvedApiUrl = api.getBaseUrl();

    // Persist credentials locally
    saveCredentials({
      apiKey: result.apiKey,
      orgId: result.orgId,
      orgName: result.orgName,
      keyPrefix: maskApiKey(result.apiKey),
      createdAt: new Date().toISOString(),
      apiUrl: resolvedApiUrl,
      appUrl: flagAppUrl,
      defaultEnvId: values['env-id'] as string | undefined,
      claimUrl: result.claimUrl,
      mcpEndpointUrl: result.mcpEndpointUrl,
      trial: {
        credits: result.trial.credits,
        expiresAt
      }
    });

    if (values.json) {
      json(result);
    } else {
      success(`Account created: ${bold(result.orgName)} (${result.orgId})`);
      info(`API key saved to ~/.hebrah/credentials (mode 0600)`);
      info(`API Endpoint: ${resolvedApiUrl}`);
      info(`Trial: ${result.trial.credits.queries} queries, ${(result.trial.credits.egressBytes / 1e9).toFixed(2)} GB egress`);
      info(`Trial expires: ${expiresAt}`);
      if (result.mcpEndpointUrl) {
        info(`MCP endpoint: ${result.mcpEndpointUrl}`);
      }
      if (result.claimUrl) {
        console.log();
        info(`Claim URL: ${bold(result.claimUrl)}`);
        info(`Share this claim link with your human team member to claim billing ownership and invite team members.`);
      }
      console.log();
      info('Next: `hebrah env create --name "Clinic Sandbox" --addons postgres` or `hebrah discover`.');
    }

    return 0;
  } catch (err) {
    if (err instanceof ApiError) {
      error(err.message);
      if (err.suggestion) info(err.suggestion);
    } else {
      error((err as Error).message);
    }
    return 4;
  }
}