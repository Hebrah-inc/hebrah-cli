// Credentials storage — ~/.hebrah/credentials (mode 0600).
//
// Wave 1 stores the hb_conn_* API key + org metadata. Future waves add
// SSO tokens, relay enrollment tokens, and wallet balance.

import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { chmodSync } from 'node:fs';

const HEBRAH_DIR = join(homedir(), '.hebrah');
const CREDENTIALS_PATH = join(HEBRAH_DIR, 'credentials');

export interface Credentials {
  apiKey: string;
  orgId: string;
  orgName: string;
  keyPrefix: string;
  createdAt: string;
  mcpEndpointUrl?: string;
  trial?: {
    credits: { queries: number; egressBytes: number };
    expiresAt: string;
  };
}

export function loadCredentials(): Credentials | null {
  if (!existsSync(CREDENTIALS_PATH)) return null;
  try {
    return JSON.parse(readFileSync(CREDENTIALS_PATH, 'utf-8'));
  } catch {
    return null;
  }
}

export function saveCredentials(creds: Credentials): void {
  mkdirSync(HEBRAH_DIR, { recursive: true, mode: 0o700 });
  mkdirSync(dirname(CREDENTIALS_PATH), { recursive: true, mode: 0o700 });
  writeFileSync(CREDENTIALS_PATH, JSON.stringify(creds, null, 2), { mode: 0o600 });
  chmodSync(CREDENTIALS_PATH, 0o600);
}

export function clearCredentials(): void {
  if (existsSync(CREDENTIALS_PATH)) {
    const fs = require('node:fs') as typeof import('node:fs');
    fs.unlinkSync(CREDENTIALS_PATH);
  }
}

export function hebrahDir(): string {
  return HEBRAH_DIR;
}

export function credentialsPath(): string {
  return CREDENTIALS_PATH;
}