// Ephemeral loopback HTTP server for CLI browser authorization callback.
//
// Protocol:
//   1. CLI starts a temporary HTTP server on 127.0.0.1:0 (ephemeral random port).
//   2. CLI generates a 32-byte cryptographic CSRF `state` nonce.
//   3. CLI opens browser to app.hebrah.com/cli/authorize?port=<port>&state=<state>&client=cli&host=<hostname>.
//   4. Web app displays consent screen; upon approval redirects to:
//      http://127.0.0.1:<port>/callback?apiKey=hb_conn_*&state=<state>&orgId=<orgId>&orgName=<orgName>
//   5. Loopback server validates state nonce, writes credentials, serves HTML, and shuts down.

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';

export interface LoopbackAuthResult {
  apiKey: string;
  orgId: string;
  orgName: string;
}

export interface LoopbackAuthServer {
  port: number;
  state: string;
  waitForCallback(timeoutMs?: number): Promise<LoopbackAuthResult>;
  close(): void;
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
  <title>Hebrah CLI — Authorized</title>
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
  <title>Hebrah CLI — Authorization Failed</title>
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
    const rawUrl = req.url ?? '/';
    const parsedUrl = new URL(rawUrl, 'http://127.0.0.1');

    if (parsedUrl.pathname === '/favicon.ico') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (parsedUrl.pathname !== '/callback') {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }

    if (settled) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(successHtml('Hebrah'));
      return;
    }

    const errorParam = parsedUrl.searchParams.get('error');
    if (errorParam) {
      settled = true;
      const desc = parsedUrl.searchParams.get('error_description') || errorParam;
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(errorHtml('Authorization Denied', desc));
      rejectCallback(new Error(`Authorization failed: ${desc}`));
      return;
    }

    const incomingState = parsedUrl.searchParams.get('state');
    if (!incomingState || incomingState !== state) {
      settled = true;
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(errorHtml('Invalid State', 'CSRF verification failed. The state parameter did not match.'));
      rejectCallback(new Error('CSRF state verification failed.'));
      return;
    }

    const apiKey = parsedUrl.searchParams.get('apiKey')?.trim();
    if (!apiKey || !apiKey.startsWith('hb_conn_')) {
      settled = true;
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(errorHtml('Invalid Key', 'No valid agent key (hb_conn_*) was provided.'));
      rejectCallback(new Error('Invalid or missing API key in authorization callback.'));
      return;
    }

    const orgId = parsedUrl.searchParams.get('orgId')?.trim() ?? '';
    const orgName = parsedUrl.searchParams.get('orgName')?.trim() ?? 'Organization';

    settled = true;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(successHtml(orgName));

    resolveCallback({
      apiKey,
      orgId,
      orgName
    });
  });

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
