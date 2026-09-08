// `hebrah signup` — create a new agent account.
//
// Usage:
//   hebrah signup --name "agent" --email "you@example.com"
//   hebrah signup --name "agent" --headless   (no email; pure agent account)
//   hebrah signup                             (interactive prompts)
//
// Returns 0 on success (saves credentials), 1 on user error, 4 on server error.

import { parseArgs } from 'node:util';
import { api, ApiError } from '../api/client.js';
import { saveCredentials } from '../config/credentials.js';
import { json, success, info, error, bold } from '../output/format.js';

interface SignupResponse {
  orgId: string;
  orgName: string;
  apiKey: string;
  trial: {
    credits: { queries: number; egressBytes: number };
    expiresAt: string;
  };
  mcpEndpointUrl?: string;
}

export default async function signup(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const { values } = parseArgs({
    args: _args,
    options: {
      name: { type: 'string' },
      email: { type: 'string' },
      headless: { type: 'boolean', default: false },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  // Interactive prompts (only if TTY and no flags)
  let orgName = values.name as string | undefined;
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
      agentName: orgName
    });

    // Persist credentials locally
    saveCredentials({
      apiKey: result.apiKey,
      orgId: result.orgId,
      orgName: result.orgName,
      keyPrefix: result.apiKey.substring(0, 14) + '...',
      createdAt: new Date().toISOString(),
      mcpEndpointUrl: result.mcpEndpointUrl,
      trial: result.trial
    });

    if (options.json) {
      json(result);
    } else {
      success(`Account created: ${bold(result.orgName)} (${result.orgId})`);
      info(`API key saved to ~/.hebrah/credentials (mode 0600)`);
      info(`Trial: ${result.trial.credits.queries} queries, ${(result.trial.credits.egressBytes / 1e9).toFixed(2)} GB egress`);
      info(`Trial expires: ${result.trial.expiresAt}`);
      if (result.mcpEndpointUrl) {
        info(`MCP endpoint: ${result.mcpEndpointUrl}`);
      }
      console.log();
      info('Next: `hebrah discover` to see available targets.');
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