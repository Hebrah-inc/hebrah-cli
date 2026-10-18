// `hebrah skill` — show the SKILL.md content (or its file path).
//
// Resolution order:
//   1. Bundled `skill.md` shipped with the npm package (offline-first)
//   2. Fetched live from `https://hebrah.com/SKILL.md` (always up-to-date)
//
// The bundled file is a snapshot of the public SKILL.md at release time;
// fetch the URL when you need the latest copy (e.g. after a Wave upgrade).

import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { error, sanitizeTerminalText } from '../output/format.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const DEFAULT_SKILL_URL = 'https://hebrah.com/SKILL.md';
const MAX_SKILL_BYTES = 2 * 1024 * 1024; // 2 MB ceiling

export default async function skill(
  _args: string[] = [],
  options: Record<string, unknown> = {}
): Promise<number> {
  // Options are forwarded from the top-level parser (index.ts) which uses
  // strict: false, so per-command flags like --path and --refresh flow in
  // here directly. Also accept flags in _args for direct programmatic calls.
  const showPath = options.path === true || _args.includes('--path');
  const refresh = options.refresh === true || _args.includes('--refresh');

  // Look for bundled SKILL.md (shipped with the npm package)
  const skillPath = join(__dirname, '..', '..', 'skill.md');

  if (showPath) {
    console.log(skillPath);
    return 0;
  }

  // --refresh: always fetch the live copy (skip bundled snapshot)
  if (refresh || !existsSync(skillPath)) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    try {
      const res = await fetch(DEFAULT_SKILL_URL, {
        redirect: 'error',
        signal: controller.signal
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const contentLen = Number(res.headers?.get?.('content-length') ?? 0);
      if (Number.isFinite(contentLen) && contentLen > MAX_SKILL_BYTES) {
        throw new Error(`SKILL.md response exceeds maximum size (${MAX_SKILL_BYTES} bytes)`);
      }
      const rawBody = await res.text();
      if (Buffer.byteLength(rawBody, 'utf8') > MAX_SKILL_BYTES) {
        throw new Error(`SKILL.md response exceeds maximum size (${MAX_SKILL_BYTES} bytes)`);
      }
      const body = sanitizeTerminalText(rawBody);
      process.stdout.write(body);
      if (!body.endsWith('\n')) process.stdout.write('\n');
      return 0;
    } catch (err) {
      error(`hebrah skill: failed to fetch ${DEFAULT_SKILL_URL}: ${err instanceof Error ? err.message : String(err)}`);
      if (existsSync(skillPath)) {
        error('Falling back to bundled snapshot');
        process.stdout.write(sanitizeTerminalText(readFileSync(skillPath, 'utf-8')));
        return 0;
      }
      error('No bundled snapshot available. Install the latest @hebrah/cli or check your network.');
      return 1;
    } finally {
      clearTimeout(timer);
    }
  }

  process.stdout.write(sanitizeTerminalText(readFileSync(skillPath, 'utf-8')));
  return 0;
}