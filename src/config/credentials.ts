// Credentials storage — ~/.hebrah/credentials (mode 0600).
//
// Security hardening (S-5):
//   - Rejects symbolic links on ~/.hebrah and ~/.hebrah/credentials via lstatSync.
//   - Enforces 0700 on directory and 0600 on credentials file.
//   - Performs atomic writes via temp file + renameSync to prevent corruption or race conditions.
//   - Stores pinned apiUrl, appUrl, and defaultEnvId for seamless multi-environment CLI usage.

import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  unlinkSync,
  chmodSync,
  lstatSync,
  renameSync
} from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { randomBytes } from 'node:crypto';

export const ALLOWED_KEY_PREFIXES = ['hb_conn_', 'hb_pat_', 'hb_live_', 'hb_test_'] as const;

const STRICT_API_KEY_RE = /^hb_(?:conn|pat|live|test)_[A-Za-z0-9._-]{8,256}$/;
const MAX_CREDENTIALS_FILE_BYTES = 65_536;

export function isValidApiKeyFormat(key: string | undefined | null): key is string {
  if (!key || typeof key !== 'string') return false;
  const trimmed = key.trim();
  return STRICT_API_KEY_RE.test(trimmed);
}

export function maskApiKey(key: string): string {
  if (!key || key.length <= 14) return 'hb_***';
  return `${key.substring(0, 14)}...`;
}

export interface Credentials {
  apiKey: string;
  orgId: string;
  orgName: string;
  keyPrefix: string;
  createdAt: string;
  apiUrl?: string;
  appUrl?: string;
  defaultEnvId?: string;
  claimUrl?: string;
  mcpEndpointUrl?: string;
  trial?: {
    credits: { queries: number; egressBytes: number };
    expiresAt: string;
  };
}

export function hebrahDir(): string {
  if (process.env.HEBRAH_CREDENTIALS_DIR) {
    return process.env.HEBRAH_CREDENTIALS_DIR;
  }
  return join(homedir(), '.hebrah');
}

export function credentialsPath(): string {
  return join(hebrahDir(), 'credentials');
}

function assertNotSymlink(targetPath: string): void {
  try {
    const st = lstatSync(targetPath);
    if (st.isSymbolicLink()) {
      throw new Error(`Security error: refusing to access symbolic link at ${targetPath}`);
    }
  } catch (err: any) {
    if (err?.code === 'ENOENT') return;
    throw err;
  }
}

export function loadCredentials(): Credentials | null {
  const dir = hebrahDir();
  const credPath = credentialsPath();
  assertNotSymlink(dir);
  assertNotSymlink(credPath);

  if (!existsSync(credPath)) return null;
  try {
    const st = lstatSync(credPath);
    if (st.isSymbolicLink()) {
      throw new Error(`Security error: refusing to read symbolic link at ${credPath}`);
    }
    if (!st.isFile()) {
      throw new Error(`Security error: credentials path ${credPath} is not a regular file`);
    }
    if (st.size > MAX_CREDENTIALS_FILE_BYTES) {
      throw new Error(`Security error: credentials file at ${credPath} exceeds maximum allowed size`);
    }
    if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
      try {
        chmodSync(credPath, 0o600);
      } catch {
        // ignore if read-only fs
      }
    }
    const parsed: unknown = JSON.parse(readFileSync(credPath, 'utf-8'));
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      Array.isArray(parsed) ||
      typeof (parsed as Record<string, unknown>).apiKey !== 'string'
    ) {
      return null;
    }
    return parsed as Credentials;
  } catch (err: any) {
    if (err?.message?.startsWith('Security error:')) {
      throw err;
    }
    return null;
  }
}

export function saveCredentials(creds: Credentials): void {
  const dir = hebrahDir();
  const credPath = credentialsPath();

  assertNotSymlink(dir);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  mkdirSync(dirname(credPath), { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') {
    try {
      chmodSync(dir, 0o700);
    } catch {
      // ignore
    }
  }

  assertNotSymlink(credPath);

  const tmpPath = `${credPath}.tmp.${process.pid}.${randomBytes(4).toString('hex')}`;
  try {
    writeFileSync(tmpPath, JSON.stringify(creds, null, 2), { encoding: 'utf-8', mode: 0o600 });
    chmodSync(tmpPath, 0o600);
    renameSync(tmpPath, credPath);
    chmodSync(credPath, 0o600);
  } catch (err) {
    try {
      if (existsSync(tmpPath)) unlinkSync(tmpPath);
    } catch {
      // ignore cleanup error
    }
    throw err;
  }
}

export function updateCredentials(patch: Partial<Credentials>): Credentials | null {
  const current = loadCredentials();
  if (!current) return null;
  const updated: Credentials = {
    ...current,
    ...patch
  };
  saveCredentials(updated);
  return updated;
}

export function clearCredentials(): void {
  const credPath = credentialsPath();
  assertNotSymlink(credPath);
  if (existsSync(credPath)) {
    unlinkSync(credPath);
  }
}