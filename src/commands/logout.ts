// `hebrah logout` — remove local credentials.

import { clearCredentials } from '../config/credentials.js';
import { success, info } from '../output/format.js';

export default async function logout(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? _args;
  const { values } = (await import('node:util')).parseArgs({
    args: argv,
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