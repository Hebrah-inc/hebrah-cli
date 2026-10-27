// Hebrah API client — HTTP wrapper for the Hebrah control plane.
//
// Security hardening (S-2 & S-6):
//   - Enforces HTTPS for all non-loopback hosts and validates trusted Hebrah hostnames.
//   - Pins credentials to the API origin they were issued for (prevents HEBRAH_API_URL token exfiltration).
//   - Validates and encodes resource IDs via safeId() and blocks path traversal ('..') in request paths.
//   - Persists and resolves apiUrl from ~/.hebrah/credentials so staging/custom envs work seamlessly.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadCredentials } from '../config/credentials.js';
import { redactSecrets, sanitizeTerminalText } from '../output/format.js';

const DEFAULT_PROD_API_URL = 'https://api.hebrah.com';
export const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function loadPackageVersion(): string {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf-8'));
    return pkg.version || '0.4.8';
  } catch {
    return '0.4.8';
  }
}

export const CLI_VERSION = loadPackageVersion();

function parseTimeoutMs(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

const DEFAULT_TIMEOUT_MS = parseTimeoutMs(process.env.HEBRAH_API_TIMEOUT_MS, 30000);

export interface RequestOptions {
  /** Per-call timeout override in milliseconds. */
  timeoutMs?: number;
}

function scrubErrorValue(val: unknown, depth = 0): unknown {
  if (depth > 6 || val === null || val === undefined) return val;
  if (typeof val === 'string') {
    return redactSecrets(sanitizeTerminalText(val));
  }
  if (Array.isArray(val)) {
    return val.map((item) => scrubErrorValue(item, depth + 1));
  }
  if (typeof val === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      out[k] = scrubErrorValue(v, depth + 1);
    }
    return out;
  }
  return val;
}

export class ApiError extends Error {
  public readonly body: unknown;
  public readonly suggestion?: string;

  constructor(
    message: string,
    public readonly statusCode: number,
    body: unknown,
    suggestion?: string
  ) {
    super(redactSecrets(sanitizeTerminalText(message)));
    this.name = 'ApiError';
    this.body = scrubErrorValue(body);
    this.suggestion =
      typeof suggestion === 'string'
        ? redactSecrets(sanitizeTerminalText(suggestion))
        : undefined;
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      statusCode: this.statusCode,
      suggestion: this.suggestion,
      body: this.body
    };
  }
}

export class TimeoutError extends Error {
  constructor(
    message: string,
    public readonly timeoutMs: number,
    public readonly suggestion?: string
  ) {
    super(redactSecrets(sanitizeTerminalText(message)));
    this.name = 'TimeoutError';
  }
}

/**
 * Validate a resource identifier (envId, connId, relayId) against path traversal
 * and URL injection before interpolating into an API path.
 */
export function safeId(rawId: string, label = 'id'): string {
  if (!rawId || typeof rawId !== 'string') {
    throw new Error(`Invalid ${label}: value is required.`);
  }
  const trimmed = rawId.trim();
  if (
    trimmed === '.' ||
    trimmed === '..' ||
    trimmed.includes('..') ||
    trimmed.includes('/') ||
    trimmed.includes('\\') ||
    !/^[a-zA-Z0-9._:-]+$/.test(trimmed)
  ) {
    throw new Error(`Invalid ${label} "${rawId}": contains disallowed characters or path traversal.`);
  }
  return encodeURIComponent(trimmed);
}

const BLOCKED_METADATA_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  '100.100.100.200',
  '[fd00:ec2::254]',
  'fd00:ec2::254'
]);

const MAX_API_RESPONSE_BYTES = 50 * 1024 * 1024; // 50 MB ceiling

export function isCloudMetadataHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (BLOCKED_METADATA_HOSTS.has(host)) return true;
  if (host.startsWith('169.254.')) return true;
  if (
    host.startsWith('::ffff:a9fe:') ||
    host.startsWith('[::ffff:a9fe:') ||
    host.startsWith('::ffff:169.254.') ||
    host.startsWith('[::ffff:169.254.')
  ) {
    return true;
  }
  return false;
}

function isTrustedHebrahHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (isCloudMetadataHost(host)) return false;
  if (LOOPBACK_HOSTS.has(host)) return true;
  if (host === 'hebrah.com' || host.endsWith('.hebrah.com')) return true;
  if (/^hebrah-[a-z0-9-]+(?:\.[a-z0-9-]+)?\.run\.app$/.test(host)) return true;
  if (process.env.HEBRAH_ALLOW_CUSTOM_HOST === '1') return true;
  return false;
}

/**
 * Validate and normalize an API or App base URL.
 * Enforces HTTPS for all non-loopback hosts and checks trusted Hebrah host patterns.
 */
export function validateApiBaseUrl(rawUrl: string): string {
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw new Error('API URL is required.');
  }
  const trimmed = rawUrl.trim();
  if (/[\x00-\x1f\x7f-\x9f\s]/.test(trimmed)) {
    throw new Error('API URL contains invalid control characters.');
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid URL format: "${rawUrl}"`);
  }

  if (parsed.username || parsed.password) {
    throw new Error('Security error: API/App URL must not contain embedded credentials.');
  }

  const host = parsed.hostname.toLowerCase();
  if (isCloudMetadataHost(host)) {
    throw new Error(
      `Security error: cloud metadata or link-local host "${host}" is strictly prohibited.`
    );
  }

  const isLoopback = LOOPBACK_HOSTS.has(host);

  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopback)) {
    throw new Error(
      `Security error: refusing cleartext HTTP connection to non-loopback host "${host}". Use https://.`
    );
  }

  if (!isTrustedHebrahHost(host)) {
    throw new Error(
      `Security error: untrusted Hebrah host "${host}". Set HEBRAH_ALLOW_CUSTOM_HOST=1 only if connecting to a self-hosted control plane.`
    );
  }

  return parsed.origin;
}

/**
 * Infer the matching API base URL from a Hebrah Dashboard (App) URL when --api-url is not explicitly passed.
 */
export function inferApiUrlFromAppUrl(appUrl: string): string {
  const origin = validateApiBaseUrl(appUrl);
  const parsed = new URL(origin);
  const host = parsed.hostname.toLowerCase();

  // Cloud Run staging/prod pattern: hebrah-staging-app-xxxx.a.run.app -> hebrah-staging-api-xxxx.a.run.app
  if (host.includes('-app-')) {
    return `${parsed.protocol}//${host.replace('-app-', '-api-')}`;
  }
  if (host === 'app.hebrah.com' || host === 'hebrah.com' || host === 'www.hebrah.com') {
    return 'https://api.hebrah.com';
  }
  if (host.startsWith('app.')) {
    return `${parsed.protocol}//api.${host.slice(4)}${parsed.port ? `:${parsed.port}` : ''}`;
  }
  if (LOOPBACK_HOSTS.has(host)) {
    return `${parsed.protocol}//${host}:8000`;
  }
  return origin;
}

class HebrahApi {
  private explicitBaseUrl: string | null = null;
  private explicitApiKey: string | null = null;

  setBaseUrl(url: string | null): void {
    this.explicitBaseUrl = url ? validateApiBaseUrl(url) : null;
  }

  getBaseUrl(): string {
    if (this.explicitBaseUrl) {
      return this.explicitBaseUrl;
    }
    if (process.env.HEBRAH_API_URL) {
      return validateApiBaseUrl(process.env.HEBRAH_API_URL);
    }
    const creds = loadCredentials();
    if (creds?.apiUrl) {
      return validateApiBaseUrl(creds.apiUrl);
    }
    return DEFAULT_PROD_API_URL;
  }

  setApiKey(key: string | null): void {
    this.explicitApiKey = key;
  }

  private resolveApiKeyForOrigin(targetOrigin: string): string | null {
    if (this.explicitApiKey) {
      return this.explicitApiKey;
    }
    if (process.env.HEBRAH_API_KEY) {
      return process.env.HEBRAH_API_KEY;
    }

    const creds = loadCredentials();
    if (!creds?.apiKey) {
      return null;
    }

    // Origin Pinning (Finding S-2): ensure saved credentials are only sent to their pinned API origin
    const pinnedOrigin = creds.apiUrl ? validateApiBaseUrl(creds.apiUrl) : DEFAULT_PROD_API_URL;
    if (targetOrigin !== pinnedOrigin) {
      try {
        const targetHost = new URL(targetOrigin).hostname.toLowerCase();
        if (LOOPBACK_HOSTS.has(targetHost)) {
          return null;
        }
      } catch {
        // fall through to throw
      }
      throw new Error(
        `Security error: stored credentials are pinned to ${pinnedOrigin}, refusing to send token to ${targetOrigin}. Run "hebrah login --api-url ${targetOrigin}" or set HEBRAH_API_KEY.`
      );
    }

    return creds.apiKey;
  }

  async get<T>(path: string, params?: Record<string, string>, opts?: RequestOptions): Promise<T> {
    return this.request<T>('GET', path, undefined, params, opts);
  }

  async post<T>(path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
    return this.request<T>('POST', path, body, undefined, opts);
  }

  async delete<T>(path: string, opts?: RequestOptions): Promise<T> {
    return this.request<T>('DELETE', path, undefined, undefined, opts);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    params?: Record<string, string>,
    opts?: RequestOptions
  ): Promise<T> {
    let decodedPath = path;
    try {
      decodedPath = decodeURIComponent(path);
    } catch {
      throw new Error(`Security error: malformed URL encoding in API request path "${path}".`);
    }

    if (
      !path.startsWith('/v1/') ||
      !decodedPath.startsWith('/v1/') ||
      path.includes('..') ||
      decodedPath.includes('..') ||
      path.includes('\\') ||
      decodedPath.includes('\\') ||
      decodedPath.includes('\0') ||
      /%2e|%2f|%5c|%00/i.test(path)
    ) {
      throw new Error(`Security error: invalid API request path "${path}".`);
    }

    const baseOrigin = this.getBaseUrl();
    const url = new URL(path, baseOrigin);

    if (url.origin !== baseOrigin || !url.pathname.startsWith('/v1/') || url.pathname.includes('..')) {
      throw new Error(`Security error: path traversal detected in "${path}".`);
    }

    if (params) {
      for (const [k, v] of Object.entries(params)) {
        url.searchParams.set(k, v);
      }
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': `hebrah-cli/${CLI_VERSION} (Node ${process.version})`
    };

    const apiKey = this.resolveApiKeyForOrigin(baseOrigin);
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    const timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        redirect: 'error',
        signal: controller.signal
      });

      const contentLength = Number(response.headers?.get?.('content-length') ?? 0);
      if (Number.isFinite(contentLength) && contentLength > MAX_API_RESPONSE_BYTES) {
        throw new Error(`Security error: API response exceeds maximum allowed size (${MAX_API_RESPONSE_BYTES} bytes).`);
      }

      const responseBody = await response.text();
      if (Buffer.byteLength(responseBody, 'utf8') > MAX_API_RESPONSE_BYTES) {
        throw new Error(`Security error: API response exceeds maximum allowed size (${MAX_API_RESPONSE_BYTES} bytes).`);
      }
      let parsed: unknown;
      try {
        parsed = responseBody ? JSON.parse(responseBody) : null;
      } catch {
        parsed = responseBody;
      }

      if (!response.ok) {
        throw mapError(response.status, parsed);
      }

      return parsed as T;
    } catch (err) {
      if (err instanceof ApiError) throw err;
      if ((err as { name?: string })?.name === 'AbortError') {
        throw new TimeoutError(
          `Request to ${method} ${url.pathname} timed out after ${timeoutMs}ms`,
          timeoutMs,
          `Increase timeout with HEBRAH_API_TIMEOUT_MS or pass { timeoutMs } to the API call.`
        );
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }
}

function mapError(status: number, body: unknown): ApiError {
  let message = `HTTP ${status}`;
  let suggestion: string | undefined;

  if (typeof body === 'object' && body !== null) {
    const obj = body as Record<string, unknown>;
    if (typeof obj.suggestion === 'string') {
      suggestion = obj.suggestion;
    }
    if (typeof obj.message === 'string') {
      message = obj.message;
    } else if ('detail' in obj) {
      const detail = obj.detail;
      if (typeof detail === 'string') {
        message = detail;
      } else if (typeof detail === 'object' && detail !== null && 'message' in detail) {
        message = String((detail as Record<string, unknown>).message);
      } else {
        message = JSON.stringify(detail);
      }
    }
  }

  message = redactSecrets(sanitizeTerminalText(message));

  switch (status) {
    case 401:
      return new ApiError(
        message !== `HTTP ${status}` ? message : 'Authentication required',
        status,
        body,
        'Run "hebrah login" or set HEBRAH_API_KEY env var.'
      );
    case 402:
      return new ApiError(
        message !== `HTTP ${status}` ? message : 'Quota exceeded',
        status,
        body,
        'Add credit at hebrah.com/pricing.'
      );
    case 403:
      return new ApiError(message !== `HTTP ${status}` ? message : 'Forbidden', status, body, suggestion);
    case 404:
      return new ApiError(message !== `HTTP ${status}` ? message : 'Not found', status, body, suggestion);
    case 409:
      return new ApiError(message !== `HTTP ${status}` ? message : 'Conflict', status, body, suggestion);
    case 410:
      return new ApiError(
        message !== `HTTP ${status}` ? message : 'Connection revoked',
        status,
        body,
        'Open a new connection with "hebrah connect".'
      );
    case 429:
      return new ApiError(
        message !== `HTTP ${status}` ? message : 'Rate limited',
        status,
        body,
        'Back off and retry.'
      );
    case 500:
    case 502:
    case 503:
    case 504:
      return new ApiError('Server error', status, body, 'Try again; if persistent, run with --debug.');
    default:
      return new ApiError(message, status, body, suggestion);
  }
}

export const api = new HebrahApi();