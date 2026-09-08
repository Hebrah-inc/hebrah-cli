// `hebrah revoke` — close a connection.
//
// Usage:
//   hebrah revoke <conn_id> [--reason <text>]
//   hebrah revoke --all [--target <target>] [--reason <text>] [--yes]
//
// Safety:
//   `--all` without `--target` revokes every active connection for the org.
//   This is destructive and irreversible. The CLI requires an interactive
//   confirmation (or `--yes`) before sending the request. When `--target`
//   is provided, the scope is narrower and confirmation is skipped.

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { api } from '../api/client.js';
import { success, error, warn } from '../output/format.js';

export default async function revoke(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? args;
  const { values } = parseArgs({
    args: argv,
    options: {
      all: { type: 'boolean', default: false },
      reason: { type: 'string' },
      target: { type: 'string' },
      yes: { type: 'boolean', short: 'y', default: false }
    },
    allowPositionals: true
  });

  const connId = argv.find((a) => !a.startsWith('-')) ?? args[0];

  try {
    if (values.all) {
      // Org-wide revoke is destructive. Require explicit confirmation
      // unless a narrower scope (--target) or --yes is provided.
      const isNarrow = Boolean(values.target);
      const skipConfirm = values.yes === true || isNarrow || !input.isTTY;

      if (!skipConfirm) {
        warn('This will revoke EVERY active connection for your organization.');
        warn('This is irreversible. In-flight queries will fail.');
        if (values.target) {
          warn(`Scope filter: target = ${values.target}`);
        }
        if (values.reason) {
          warn(`Reason: ${values.reason}`);
        }
        const rl = createInterface({ input, output });
        const answer = (await rl.question('Type "revoke all" to confirm: ')).trim();
        rl.close();
        if (answer !== 'revoke all') {
          error('Aborted.');
          return 1;
        }
      }

      const result = await api.post<{ revokedCount: number }>('/v1/connections/revoke-all', {
        reason: values.reason,
        target: values.target
      });
      success(`Revoked ${result.revokedCount} connection${result.revokedCount === 1 ? '' : 's'}.`);
      return 0;
    }

    if (!connId) {
      error('hebrah revoke: connection_id required (or use --all)');
      return 1;
    }

    await api.post(`/v1/connections/${connId}/revoke`, {
      reason: values.reason
    });
    success(`Revoked connection ${connId}.`);
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 4;
  }
}