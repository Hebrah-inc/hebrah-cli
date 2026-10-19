// Argv helper — extracts the first non-flag positional and the full flag
// argv slice from the forwarded `options` object.
//
// Background: the top-level parser in src/index.ts uses `strict: false`
// so unknown flags flow through, but any flag with a string value (like
// --sql "SELECT 1") has its value silently hoisted into `positionals` by
// the top-level parser. To avoid this, index.ts forwards the raw argv
// slice as `options._argv` and each command re-parses that instead of
// the polluted `args` parameter.

import { api, inferApiUrlFromAppUrl, safeId, validateApiBaseUrl } from '../api/client.js';
import { loadCredentials } from '../config/credentials.js';

export function getPositional(args: string[], options: Record<string, unknown> = {}): string | undefined {
  const argv = (options?._argv as string[] | undefined) ?? args;
  return argv.find((a) => !a.startsWith('-') && !a.includes('='));
}

export function getArgv(options: Record<string, unknown> = {}, fallback: string[] = []): string[] {
  return (options?._argv as string[] | undefined) ?? fallback;
}

export function resolveAppUrl(explicitAppUrl?: string, explicitApiUrl?: string): string {
  if (explicitAppUrl) {
    return validateApiBaseUrl(explicitAppUrl);
  }
  if (process.env.HEBRAH_APP_URL) {
    return validateApiBaseUrl(process.env.HEBRAH_APP_URL);
  }
  const savedAppUrl = loadCredentials()?.appUrl;
  if (savedAppUrl) {
    return validateApiBaseUrl(savedAppUrl);
  }
  const apiUrl = explicitApiUrl ?? process.env.HEBRAH_API_URL ?? loadCredentials()?.apiUrl ?? '';
  if (apiUrl.includes('localhost') || apiUrl.includes('127.0.0.1')) {
    return 'http://localhost:3000';
  }
  if (apiUrl.includes('-api-')) {
    return validateApiBaseUrl(apiUrl.replace('-api-', '-app-'));
  }
  return 'https://app.hebrah.com';
}

export interface AuthUrlFlagResult {
  appUrl: string;
  flagAppUrl?: string;
  flagApiUrl?: string;
  envId?: string;
}

export function applyAuthUrlFlags(opts: {
  appUrl?: string;
  apiUrl?: string;
  envId?: string;
  inferFromResolvedAppUrl?: boolean;
}): AuthUrlFlagResult {
  let flagAppUrl = opts.appUrl;
  let flagApiUrl = opts.apiUrl;
  let envId = opts.envId;

  if (envId) {
    safeId(envId, 'env-id');
    envId = envId.trim();
  }
  if (flagAppUrl) {
    flagAppUrl = validateApiBaseUrl(flagAppUrl);
  }
  if (!flagApiUrl && flagAppUrl) {
    flagApiUrl = inferApiUrlFromAppUrl(flagAppUrl);
  }
  const appUrl = resolveAppUrl(flagAppUrl, flagApiUrl);
  if (opts.inferFromResolvedAppUrl && !flagApiUrl && appUrl) {
    const inferred = inferApiUrlFromAppUrl(appUrl);
    if (inferred && !process.env.HEBRAH_API_URL) {
      flagApiUrl = inferred;
    }
  }
  if (flagApiUrl) {
    flagApiUrl = validateApiBaseUrl(flagApiUrl);
    api.setBaseUrl(flagApiUrl);
  }
  return { appUrl, flagAppUrl, flagApiUrl, envId };
}