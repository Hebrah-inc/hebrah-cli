// Ephemeral loopback HTTP server for CLI browser authorization callback.
//
// Protocol:
//   1. CLI starts a temporary HTTP server on 127.0.0.1:0 (ephemeral random port).
//   2. CLI generates a 32-byte cryptographic CSRF `state` nonce.
//   3. CLI opens browser to <appUrl>/cli/authorize?port=<port>&state=<state>&client=cli&host=<hostname>.
//   4. Web app displays consent screen; upon approval redirects to:
//      http://127.0.0.1:<port>/callback?apiKey=hb_conn_*&state=<state>&orgId=<orgId>&orgName=<orgName>&apiUrl=<apiUrl>
//   5. Loopback server validates state nonce in constant time, scrubs URL history via replaceState,
//      serves no-store HTML, and shuts down.

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { isValidApiKeyFormat } from '../config/credentials.js';
import { safeId, validateApiBaseUrl } from '../api/client.js';
import { sanitizeTerminalText } from '../output/format.js';

export interface LoopbackAuthResult {
  apiKey: string;
  orgId: string;
  orgName: string;
  apiUrl?: string;
  envId?: string;
}

export interface LoopbackAuthServer {
  port: number;
  state: string;
  waitForCallback(timeoutMs?: number): Promise<LoopbackAuthResult>;
  close(): void;
}

const ALLOWED_LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);

const SECURITY_HEADERS: Record<string, string> = {
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  'Pragma': 'no-cache',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"
};

export function isValidLoopbackHostHeader(hostHeader: string | undefined): boolean {
  if (!hostHeader) return false;
  const trimmed = hostHeader.trim().toLowerCase();
  if (!trimmed) return false;
  try {
    const parsed = new URL(`http://${trimmed}`);
    return ALLOWED_LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase());
  } catch {
    return false;
  }
}

function constantTimeStateMatch(incoming: string | null, expected: string): boolean {
  if (!incoming || typeof incoming !== 'string') return false;
  const a = Buffer.from(incoming, 'utf-8');
  const b = Buffer.from(expected, 'utf-8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function successHtml(orgName: string): string {
  const escaped = escapeHtml(orgName);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>Hebrah CLI — Authorized</title>
  <script>
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, '', '/callback');
    }
  </script>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #09090b;
      color: #f4f4f5;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 16px;
      box-sizing: border-box;
    }
    .card {
      max-width: 440px;
      width: 100%;
      padding: 36px 32px;
      border: 1px solid #27272a;
      border-radius: 12px;
      background-color: #18181b;
      text-align: center;
      box-shadow: 0 4px 24px rgba(0,0,0,0.4);
    }
    .badge {
      display: inline-block;
      padding: 4px 14px;
      border-radius: 9999px;
      font-size: 13px;
      font-weight: 600;
      background-color: rgba(52, 211, 153, 0.15);
      color: #34d399;
      margin-bottom: 18px;
    }
    h1 { font-size: 20px; font-weight: 600; margin: 0 0 12px 0; color: #ffffff; }
    p { font-size: 14px; line-height: 1.6; color: #a1a1aa; margin: 0 0 16px 0; }
    .org { color: #ffffff; font-weight: 600; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">✔ Authorized</div>
    <h1>Authentication Successful</h1>
    <p>Connected to <span class="org">${escaped}</span>.</p>
    <p>You can close this tab and return to your terminal.</p>
  </div>
</body>
</html>`;
}

function errorHtml(title: string, message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>Hebrah CLI — Authorization Failed</title>
  <script>
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, '', '/callback');
    }
  </script>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #09090b;
      color: #f4f4f5;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 16px;
      box-sizing: border-box;
    }
    .card {
      max-width: 440px;
      width: 100%;
      padding: 36px 32px;
      border: 1px solid #7f1d1d;
      border-radius: 12px;
      background-color: #18181b;
      text-align: center;
      box-shadow: 0 4px 24px rgba(0,0,0,0.4);
    }
    .badge {
      display: inline-block;
      padding: 4px 14px;
      border-radius: 9999px;
      font-size: 13px;
      font-weight: 600;
      background-color: rgba(239, 68, 68, 0.15);
      color: #ef4444;
      margin-bottom: 18px;
    }
    h1 { font-size: 20px; font-weight: 600; margin: 0 0 12px 0; color: #ffffff; }
    p { font-size: 14px; line-height: 1.6; color: #a1a1aa; margin: 0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">✖ Failed</div>
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
  </div>
</body>
</html>`;
}

/**
 * Start an ephemeral loopback HTTP server on 127.0.0.1:0.
 */
export async function startLoopbackAuth(): Promise<LoopbackAuthServer> {
  const state = randomBytes(32).toString('hex');

  let server: Server;
  let resolveCallback: (value: LoopbackAuthResult) => void;
  let rejectCallback: (reason: Error) => void;
  let settled = false;

  const callbackPromise = new Promise<LoopbackAuthResult>((resolve, reject) => {
    resolveCallback = resolve;
    rejectCallback = reject;
  });

  server = createServer((req: IncomingMessage, res: ServerResponse) => {
    req.socket.setTimeout(5_000, () => {
      req.destroy();
    });

    // 1. DNS Rebinding guard: reject non-loopback Host headers without aborting the listener
    if (!isValidLoopbackHostHeader(req.headers.host)) {
      res.writeHead(403, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Forbidden: invalid Host header (DNS rebinding protection)');
      return;
    }

    // 2. Cross-Origin Subresource DoS guard: block browser <img>/<script>/<iframe>/fetch(no-cors) probes
    const secFetchMode = req.headers['sec-fetch-mode'];
    const secFetchDest = req.headers['sec-fetch-dest'];
    const secFetchSite = req.headers['sec-fetch-site'];
    const blockedDests = new Set([
      'image',
      'script',
      'iframe',
      'frame',
      'style',
      'audio',
      'video',
      'embed',
      'object'
    ]);
    if (
      secFetchMode === 'no-cors' ||
      (typeof secFetchDest === 'string' && blockedDests.has(secFetchDest)) ||
      (secFetchSite === 'cross-site' && secFetchMode !== 'navigate')
    ) {
      res.writeHead(403, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Forbidden: cross-origin subresource requests are not permitted');
      return;
    }

    const rawUrl = req.url ?? '/';
    if (rawUrl.length > 4096) {
      res.writeHead(414, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('URI Too Long');
      return;
    }
    const parsedUrl = new URL(rawUrl, 'http://127.0.0.1');

    // Ignore non-GET probes (HEAD/OPTIONS preflight) so browser prefetchers don't disrupt auth
    if (req.method && req.method !== 'GET') {
      res.writeHead(204, SECURITY_HEADERS);
      res.end();
      return;
    }

    if (parsedUrl.pathname === '/favicon.ico') {
      res.writeHead(204, SECURITY_HEADERS);
      res.end();
      return;
    }

    if (parsedUrl.pathname !== '/callback') {
      res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not Found');
      return;
    }

    if (settled) {
      res.writeHead(200, SECURITY_HEADERS);
      res.end(successHtml('Hebrah'));
      return;
    }

    const incomingState = parsedUrl.searchParams.get('state');
    const errorParam = parsedUrl.searchParams.get('error');
    if (errorParam) {
      if (incomingState !== null && !constantTimeStateMatch(incomingState, state)) {
        res.writeHead(400, SECURITY_HEADERS);
        res.end(errorHtml('Invalid State', 'CSRF verification failed. The state parameter did not match.'));
        return;
      }
      settled = true;
      const desc = sanitizeTerminalText(
        parsedUrl.searchParams.get('error_description') || errorParam
      ).slice(0, 256);
      res.writeHead(400, SECURITY_HEADERS);
      res.end(errorHtml('Authorization Denied', desc));
      rejectCallback(new Error(`Authorization failed: ${desc}`));
      return;
    }

    const rawKey = (parsedUrl.searchParams.get('apiKey') ?? parsedUrl.searchParams.get('key'))?.trim();

    // If a blank probe hits /callback with neither state nor apiKey, return 400 without killing listener
    if (!incomingState && !rawKey) {
      res.writeHead(400, SECURITY_HEADERS);
      res.end(errorHtml('Missing Parameters', 'Awaiting browser authorization callback.'));
      return;
    }

    if (!constantTimeStateMatch(incomingState, state)) {
      settled = true;
      res.writeHead(400, SECURITY_HEADERS);
      res.end(errorHtml('Invalid State', 'CSRF verification failed. The state parameter did not match.'));
      rejectCallback(new Error('CSRF state verification failed.'));
      return;
    }

    if (!isValidApiKeyFormat(rawKey)) {
      settled = true;
      res.writeHead(400, SECURITY_HEADERS);
      res.end(errorHtml('Invalid Key', 'No valid Hebrah key (hb_conn_* or hb_pat_*) was provided.'));
      rejectCallback(new Error('Invalid or missing API key in authorization callback.'));
      return;
    }

    const orgId = sanitizeTerminalText(
      (parsedUrl.searchParams.get('orgId') ?? parsedUrl.searchParams.get('org_id'))?.trim() ?? ''
    ).slice(0, 128);
    const orgName = sanitizeTerminalText(
      (parsedUrl.searchParams.get('orgName') ?? parsedUrl.searchParams.get('org_name'))?.trim() ?? 'Organization'
    ).slice(0, 128);
    const rawApiUrl = (parsedUrl.searchParams.get('apiUrl') ?? parsedUrl.searchParams.get('api_url'))?.trim() || undefined;
    let apiUrl: string | undefined;
    if (rawApiUrl) {
      try {
        apiUrl = validateApiBaseUrl(rawApiUrl);
      } catch {
        apiUrl = undefined;
      }
    }
    const rawEnvId = (parsedUrl.searchParams.get('envId') ?? parsedUrl.searchParams.get('env_id'))?.trim() || undefined;
    let envId: string | undefined;
    if (rawEnvId) {
      try {
        safeId(rawEnvId, 'envId');
        envId = rawEnvId;
      } catch {
        envId = undefined;
      }
    }

    settled = true;
    res.writeHead(200, SECURITY_HEADERS);
    res.end(successHtml(orgName));

    const result: LoopbackAuthResult = {
      apiKey: rawKey,
      orgId,
      orgName
    };
    if (apiUrl) result.apiUrl = apiUrl;
    if (envId) result.envId = envId;

    resolveCallback(result);
  });

  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;

  await new Promise<void>((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => resolve());
    server.once('error', reject);
  });

  const address = server.address() as AddressInfo;
  const port = address.port;

  function closeServer() {
    try {
      server.close();
    } catch {
      // ignore if already closed
    }
  }

  return {
    port,
    state,
    async waitForCallback(timeoutMs = 120_000): Promise<LoopbackAuthResult> {
      let timeoutId: NodeJS.Timeout | null = null;

      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutId = setTimeout(() => {
          if (!settled) {
            settled = true;
            reject(new Error(`Login timed out after ${Math.round(timeoutMs / 1000)} seconds.`));
          }
        }, timeoutMs);
        timeoutId.unref?.();
      });

      try {
        return await Promise.race([callbackPromise, timeoutPromise]);
      } finally {
        if (timeoutId) clearTimeout(timeoutId);
        closeServer();
      }
    },
    close: closeServer
  };
}
