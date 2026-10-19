// System default browser launcher for macOS, Windows, and Linux.
// Security:
//   - Strictly validates URL protocol (https: or loopback http: only) and rejects control chars.
//   - Spawns OS opener directly with shell: false and argument array (prevents shell command injection).

import { spawn } from 'node:child_process';
import { platform } from 'node:os';
import { LOOPBACK_HOSTS, isCloudMetadataHost } from '../api/client.js';

/**
 * Validate that a URL is safe to open in the user's browser.
 * Rejects control characters, javascript:/file:/data: schemes, cloud metadata hosts, and non-loopback cleartext http:.
 */
export function validateBrowserUrl(rawUrl: string): string {
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw new Error('Browser URL is required.');
  }
  const trimmed = rawUrl.trim();
  if (/[\x00-\x1f\x7f-\x9f\s`$"';|<>\\]/.test(trimmed)) {
    throw new Error('Browser URL contains unsafe or disallowed characters.');
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error('Invalid browser URL format.');
  }

  if (parsed.username || parsed.password) {
    throw new Error('Browser URL must not contain embedded credentials.');
  }

  const host = parsed.hostname.toLowerCase();
  if (isCloudMetadataHost(host)) {
    throw new Error(`Security error: refusing to open cloud metadata or link-local host "${host}".`);
  }

  if (parsed.protocol === 'https:') {
    return parsed.toString();
  }
  if (parsed.protocol === 'http:' && LOOPBACK_HOSTS.has(host)) {
    return parsed.toString();
  }

  throw new Error(
    `Refusing to open untrusted URL protocol "${parsed.protocol}" (only https:// or loopback http:// allowed).`
  );
}

/**
 * Launch the user's default browser to open the given URL without invoking a shell.
 * Returns true if the opener process was spawned cleanly, false otherwise.
 */
export function openBrowser(url: string): Promise<boolean> {
  let safeUrl: string;
  try {
    safeUrl = validateBrowserUrl(url);
  } catch {
    return Promise.resolve(false);
  }

  const osPlatform = platform();
  let cmd: string;
  let args: string[];

  if (osPlatform === 'darwin') {
    cmd = 'open';
    args = [safeUrl];
  } else if (osPlatform === 'win32') {
    cmd = 'rundll32';
    args = ['url.dll,FileProtocolHandler', safeUrl];
  } else {
    cmd = 'xdg-open';
    args = [safeUrl];
  }

  return new Promise<boolean>((resolve) => {
    let settled = false;
    const finish = (ok: boolean) => {
      if (!settled) {
        settled = true;
        resolve(ok);
      }
    };

    let child;
    try {
      child = spawn(cmd, args, {
        detached: true,
        stdio: 'ignore',
        shell: false
      });
    } catch {
      finish(false);
      return;
    }

    child.once('error', () => finish(false));
    child.once('spawn', () => {
      child.unref();
      const timer = setTimeout(() => finish(true), 250);
      timer.unref?.();
    });
    child.once('exit', (code: number | null) => {
      if (code !== null && code !== 0) {
        finish(false);
      } else {
        finish(true);
      }
    });
  });
}
