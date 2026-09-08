// `hebrah logout` — remove local credentials.
//
// Usage:
//   hebrah logout                          (remove local credentials only)
//   hebrah logout --revoke-all             (also revoke all server-side connections)
//
// Note: `hebrah logout` only removes `~/.hebrah/credentials`. If
// `HEBRAH_API_KEY` is set in the environment, subsequent commands will
// still authenticate via that env var (process-bound). Unset it with
// `unset HEBRAH_API_KEY` (POSIX) or `Remove-Item Env:HEBRAH_API_KEY`
// (PowerShell) to fully log out.

import { clearCredentials } from '../config/credentials.js';
import { success, info, warn } from '../output/format.js';

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

  if (process.env.HEBRAH_API_KEY) {
    warn('HEBRAH_API_KEY env var is still set. Unset it to fully log out:');
    info('  POSIX:     unset HEBRAH_API_KEY');
    info('  PowerShell: Remove-Item Env:HEBRAH_API_KEY');
  }

  if (values['revoke-all']) {
    info('(revoke-all not yet implemented — use `hebrah revoke --all`)');
  }

  return 0;
}