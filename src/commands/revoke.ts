// `hebrah revoke` — close a connection.

import { parseArgs } from 'node:util';
import { api } from '../api/client.js';
import { success, error } from '../output/format.js';

export default async function revoke(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const { values } = parseArgs({
    args,
    options: {
      all: { type: 'boolean', default: false },
      reason: { type: 'string' },
      target: { type: 'string' }
    },
    allowPositionals: true
  });

  const connId = args[0];

  try {
    if (values.all) {
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