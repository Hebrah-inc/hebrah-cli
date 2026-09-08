// `hebrah logout` — remove local credentials.

import { clearCredentials } from '../config/credentials.js';
import { success, info } from '../output/format.js';

export default async function logout(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const { values } = (await import('node:util')).parseArgs({
    args: _args,
    options: {
      'revoke-all': { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  clearCredentials();
  success('Logged out. Local credentials removed.');

  if (values['revoke-all']) {
    info('(revoke-all not yet implemented — use `hebrah revoke --all`)');
  }

  return 0;
}