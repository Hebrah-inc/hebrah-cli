// `hebrah signup` — create a new agent account.
//
// Usage:
//   hebrah signup --name "agent" --email "you@company.com"
//   hebrah signup --name "agent" --headless   (no email; pure agent account)
//   hebrah signup                             (interactive prompts)
//
// Returns 0 on success (saves credentials), 1 on user error, 4 on server error.

import { parseArgs } from 'node:util';
import { api, ApiError } from '../api/client.js';
import { saveCredentials, maskApiKey } from '../config/credentials.js';
import { json, success, info, error, bold, sanitizeTerminalText } from '../output/format.js';
import { validateBrowserUrl } from '../util/browser.js';
import { applyAuthUrlFlags, getArgv } from '../util/args.js';

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
  options: Record<string, unknown> = {}
): Promise<number> {
  const argv = getArgv(options, _args);
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

  let flagAppUrl: string | undefined;
  let defaultEnvId: string | undefined;
  try {
    const resolved = applyAuthUrlFlags({
      appUrl: values['app-url'] as string | undefined,
      apiUrl: values['api-url'] as string | undefined,
      envId: values['env-id'] as string | undefined
    });
    flagAppUrl = resolved.flagAppUrl;
    defaultEnvId = resolved.envId;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }

  // Interactive prompts (only if TTY and no flags)
  let orgName = (values.name ?? values['agent-name']) as string | undefined;
  let inviteEmail = values.email as string | undefined;

  if (!orgName && process.stdin.isTTY && !values.headless) {
    const { createInterface } = await import('node:readline/promises');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    try {
      orgName = await rl.question('Organization name: ');
    } finally {
      rl.close();
    }
  }

  if (!orgName || orgName.trim().length < 2) {
    error('Organization name must be at least 2 characters.');
    return 1;
  }
  orgName = orgName.trim();

  if (!values.headless) {
    if (!inviteEmail && process.stdin.isTTY) {
      const { createInterface } = await import('node:readline/promises');
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        inviteEmail = await rl.question('Invite email (for billing ownership): ');
      } finally {
        rl.close();
      }
    }
    if (!inviteEmail || !inviteEmail.includes('@')) {
      error('A valid email is required for billing ownership. Use --headless to skip.');
      return 1;
    }
    inviteEmail = inviteEmail.trim();
  }

  const safeSlug = orgName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'agent';

  try {
    const result = await api.post<SignupResponse>('/v1/agent/account', {
      orgName,
      inviteEmail: inviteEmail ?? `${safeSlug}@hebrah-agent.io`,
      headless: values.headless ?? false,
      agentName: (values['agent-name'] as string | undefined) ?? orgName
    });

    const expiresAt =
      result.trial.expiresAt ??
      result.trial.expires_at ??
      new Date(Date.now() + 14 * 86400000).toISOString();

    const resolvedApiUrl = api.getBaseUrl();
    const keyPrefix = maskApiKey(result.apiKey);

    let safeClaimUrl: string | undefined;
    if (result.claimUrl) {
      try {
        safeClaimUrl = validateBrowserUrl(sanitizeTerminalText(result.claimUrl));
      } catch {
        safeClaimUrl = undefined;
      }
    }

    let safeMcpUrl: string | undefined;
    if (result.mcpEndpointUrl) {
      try {
        safeMcpUrl = validateBrowserUrl(sanitizeTerminalText(result.mcpEndpointUrl));
      } catch {
        safeMcpUrl = undefined;
      }
    }

    const safeOrgId = sanitizeTerminalText(result.orgId);
    const safeOrgName = sanitizeTerminalText(result.orgName);

    // Persist credentials locally
    saveCredentials({
      apiKey: result.apiKey,
      orgId: safeOrgId,
      orgName: safeOrgName,
      keyPrefix,
      createdAt: new Date().toISOString(),
      apiUrl: resolvedApiUrl,
      appUrl: flagAppUrl,
      defaultEnvId,
      claimUrl: safeClaimUrl,
      mcpEndpointUrl: safeMcpUrl,
      trial: {
        credits: result.trial.credits,
        expiresAt
      }
    });

    if (values.json) {
      const { apiKey: _rawKey, ...safeResult } = result;
      void _rawKey;
      json({
        ...safeResult,
        orgId: safeOrgId,
        orgName: safeOrgName,
        claimUrl: safeClaimUrl,
        mcpEndpointUrl: safeMcpUrl,
        keyPrefix
      });
    } else {
      success(`Account created: ${bold(safeOrgName)} (${safeOrgId})`);
      info(`API key saved to ~/.hebrah/credentials (mode 0600)`);
      info(`API Endpoint: ${resolvedApiUrl}`);
      info(`Trial: ${result.trial.credits.queries} queries, ${(result.trial.credits.egressBytes / 1e9).toFixed(2)} GB egress`);
      info(`Trial expires: ${expiresAt}`);
      if (safeMcpUrl) {
        info(`MCP endpoint: ${safeMcpUrl}`);
      }
      if (safeClaimUrl) {
        console.log();
        info(`Claim URL: ${bold(safeClaimUrl)}`);
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