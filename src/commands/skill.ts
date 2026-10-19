// `hebrah skill` — show the SKILL.md content (or its file path).
//
// Resolution order:
//   1. Bundled `skill.md` shipped with the npm package (offline-first)
//   2. Fetched live from `https://hebrah.com/SKILL.md` (always up-to-date)
//
// The bundled file is a snapshot of the public SKILL.md at release time;
// fetch the URL when you need the latest copy (e.g. after a Wave upgrade).

import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { error, redactSecrets, sanitizeTerminalText } from '../output/format.js';
import { getArgv } from '../util/args.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const DEFAULT_SKILL_URL = 'https://hebrah.com/SKILL.md';
const MAX_SKILL_BYTES = 2 * 1024 * 1024; // 2 MB ceiling

function readSafeBundledSkill(skillPath: string): string {
  const st = lstatSync(skillPath);
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new Error(`Security error: Refusing to read non-regular or symlinked skill file (${skillPath})`);
  }
  return redactSecrets(sanitizeTerminalText(readFileSync(skillPath, 'utf-8')));
}

export default async function skill(
  _args: string[] = [],
  options: Record<string, unknown> = {}
): Promise<number> {
  const argv = getArgv(options, _args);
  const { values } = parseArgs({
    args: argv,
    options: {
      path: { type: 'boolean', default: false },
      refresh: { type: 'boolean', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  const showPath = options.path === true || values.path === true || _args.includes('--path');
  const refresh = options.refresh === true || values.refresh === true || _args.includes('--refresh');

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
      const body = redactSecrets(sanitizeTerminalText(rawBody));
      process.stdout.write(body);
      if (!body.endsWith('\n')) process.stdout.write('\n');
      return 0;
    } catch (err) {
      error(`hebrah skill: failed to fetch ${DEFAULT_SKILL_URL}: ${err instanceof Error ? err.message : String(err)}`);
      if (existsSync(skillPath)) {
        try {
          error('Falling back to bundled snapshot');
          process.stdout.write(readSafeBundledSkill(skillPath));
          return 0;
        } catch (fallbackErr) {
          error((fallbackErr as Error).message);
          return 1;
        }
      }
      error('No bundled snapshot available. Install the latest @hebrah/cli or check your network.');
      return 1;
    } finally {
      clearTimeout(timer);
    }
  }

  try {
    process.stdout.write(readSafeBundledSkill(skillPath));
    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}