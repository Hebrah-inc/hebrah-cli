import { writeFileSync, lstatSync, chmodSync, renameSync, unlinkSync } from 'node:fs';
import { resolve as resolvePath, basename, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { api, safeId } from '../api/client.js';
import { loadCredentials } from '../config/credentials.js';
import { sanitizeTerminalText } from '../output/format.js';

export interface EnvironmentSummary {
  id: string;
  name: string;
  status: string;
  clinic_type?: string;
  addons?: string[];
  database_packs?: string[];
  wireguard_ip?: string;
  db_schema?: string;
}

export function normalizeWireguardKey(rawKey: string, clampPrivate = false): string {
  const trimmed = rawKey.trim();
  if (trimmed.length !== 43 && trimmed.length !== 44) return trimmed;
  const stdB64 = trimmed.replace(/-/g, '+').replace(/_/g, '/');
  const padded = stdB64 + '='.repeat((4 - (stdB64.length % 4)) % 4);
  try {
    const buf = Buffer.from(padded, 'base64');
    if (buf.length === 32) {
      if (clampPrivate) {
        buf[0] &= 248;
        buf[31] &= 127;
        buf[31] |= 64;
      }
      return buf.toString('base64');
    }
  } catch {
    // fallback if not 32-byte base64
  }
  return padded;
}

export function normalizeWireguardConfig(configText: string): string {
  if (!configText) return configText;
  return configText
    .replace(/^(\s*PrivateKey\s*=\s*)([^\r\n#]+)$/gim, (_m, prefix: string, key: string) => {
      if (key.includes('<redacted')) return `${prefix}${key}`;
      return `${prefix}${normalizeWireguardKey(key, true)}`;
    })
    .replace(/^(\s*PublicKey\s*=\s*)([^\r\n#]+)$/gim, (_m, prefix: string, key: string) => {
      return `${prefix}${normalizeWireguardKey(key, false)}`;
    })
    .replace(/^(\s*Endpoint\s*=\s*)vpn\.hebrah\.internal:(\d+)\s*$/gim, '$1127.0.0.1:$2')
    .replace(/^\s*DNS\s*=\s*10\.42\.0\.1\s*\r?\n/gim, '');
}

export function normalizeWireguardFilename(rawFilename: string | undefined, envId: string): string {
  const fallback = `hb-env-${envId.replace(/-/g, '').slice(0, 8)}.conf`;
  if (!rawFilename) return fallback;
  const base = basename(rawFilename.trim());
  const stem = base.replace(/\.conf$/i, '');
  if (!stem || stem.length > 15 || !/^[a-zA-Z0-9_-]+$/.test(stem)) {
    return fallback;
  }
  return `${stem}.conf`;
}

export function redactWireguardPrivateKey(configText: string): string {
  return configText.replace(
    /^(\s*PrivateKey\s*=\s*).+$/gim,
    '$1<redacted — use --out ./wg.conf or --reveal-private-key>'
  );
}

export function writeWireguardConfigFile(outPath: string, configText: string): string {
  const resolved = resolvePath(outPath);
  const parentDir = dirname(resolved);

  const parentStat = lstatSync(parentDir);
  if (parentStat.isSymbolicLink()) {
    throw new Error(
      `Security error: Refusing to write WireGuard private key inside symlinked directory (${parentDir})`
    );
  }
  if (!parentStat.isDirectory()) {
    throw new Error(
      `Security error: Parent path is not a directory (${parentDir})`
    );
  }

  try {
    const st = lstatSync(resolved);
    if (st.isSymbolicLink()) {
      throw new Error(
        `Security error: Refusing to write WireGuard private key to symlink (${resolved})`
      );
    }
    if (!st.isFile()) {
      throw new Error(
        `Security error: Refusing to write WireGuard private key to non-regular file (${resolved})`
      );
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw err;
    }
  }

  const cleanConfig = sanitizeTerminalText(configText);
  const tmpFile = `${resolved}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`;
  try {
    writeFileSync(tmpFile, cleanConfig, { encoding: 'utf-8', mode: 0o600, flag: 'wx' });
    try {
      chmodSync(tmpFile, 0o600);
    } catch {
      // Ignore on non-POSIX filesystems
    }
    renameSync(tmpFile, resolved);
  } catch (err) {
    try {
      unlinkSync(tmpFile);
    } catch {
      // Ignore cleanup errors
    }
    throw err;
  }
  return resolved;
}

export async function ensureEnvironmentOrigin(
  explicitId?: string,
  options?: Record<string, unknown>
): Promise<void> {
  if (
    process.env.VITEST ||
    options?.['api-url'] ||
    process.env.HEBRAH_API_URL ||
    api.getBaseUrl() === 'http://localhost:8000'
  ) {
    return;
  }

  const savedApiUrl = loadCredentials()?.apiUrl ?? '';
  const allowLocalFallback =
    process.env.HEBRAH_ALLOW_LOCAL_FALLBACK === '1' ||
    savedApiUrl.includes('localhost') ||
    savedApiUrl.includes('127.0.0.1');

  if (!allowLocalFallback) {
    return;
  }

  const probePath = explicitId
    ? `/v1/environments/${safeId(explicitId, 'environment_id')}`
    : '/v1/environments';

  try {
    const res = await api.get<unknown>(probePath, undefined, { timeoutMs: 3500 });
    if (explicitId && res) return;
    if (!explicitId && Array.isArray(res) && res.length > 0) return;
  } catch {
    // Primary origin didn't have the environment or wasn't reachable — probe local dev control plane
  }

  const prevUrl = api.getBaseUrl();
  try {
    api.setBaseUrl('http://localhost:8000');
    await api.get<unknown>(probePath, undefined, { timeoutMs: 2000 });
  } catch {
    api.setBaseUrl(prevUrl);
  }
}

/**
 * Synchronously resolve an environment ID from an explicit CLI argument, `HEBRAH_ENV_ID`, or `~/.hebrah/credentials`.
 */
export function resolveStaticEnvId(explicitId?: string): string | undefined {
  if (explicitId && explicitId.trim().length > 0) {
    return explicitId.trim();
  }
  if (process.env.HEBRAH_ENV_ID && process.env.HEBRAH_ENV_ID.trim().length > 0) {
    return process.env.HEBRAH_ENV_ID.trim();
  }
  const saved = loadCredentials()?.defaultEnvId;
  if (saved && saved.trim().length > 0) {
    return saved.trim();
  }
  return undefined;
}

/**
 * Resolve an environment ID from an explicit CLI argument, `HEBRAH_ENV_ID`, `~/.hebrah/credentials`,
 * or fall back to querying active environments via `GET /v1/environments`.
 */
export async function resolveEnvironmentId(
  explicitId?: string,
  options?: Record<string, unknown>
): Promise<string> {
  await ensureEnvironmentOrigin(explicitId, options);
  const staticId = resolveStaticEnvId(explicitId);
  if (staticId) {
    return staticId;
  }
  const res = await api.get<
    EnvironmentSummary[] | { environments: EnvironmentSummary[] }
  >('/v1/environments');
  const envs = Array.isArray(res) ? res : (res?.environments ?? []);
  const active =
    envs.find((e) => e.status === 'active' || e.status === 'running') ?? envs[0];
  if (!active) {
    throw new Error(
      'No active Isolated Health Environment found. Pass <environment_id> or run "hebrah env list".'
    );
  }
  return active.id;
}
