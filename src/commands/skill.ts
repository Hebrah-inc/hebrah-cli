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

const __dirname = dirname(fileURLToPath(import.meta.url));

const DEFAULT_SKILL_URL = 'https://hebrah.com/SKILL.md';

export default async function skill(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  // Options are forwarded from the top-level parser (index.ts) which uses
  // strict: false, so per-command flags like --path and --refresh flow in
  // here directly. No need to re-parse argv.
  const showPath = options.path === true;
  const refresh = options.refresh === true;

  // Look for bundled SKILL.md (shipped with the npm package)
  const skillPath = join(__dirname, '..', '..', 'skill.md');

  if (showPath) {
    console.log(skillPath);
    return 0;
  }

  // --refresh: always fetch the live copy (skip bundled snapshot)
  if (refresh || !existsSync(skillPath)) {
    try {
      const res = await fetch(DEFAULT_SKILL_URL);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const body = await res.text();
      process.stdout.write(body);
      if (!body.endsWith('\n')) process.stdout.write('\n');
      return 0;
    } catch (err) {
      console.error(`hebrah skill: failed to fetch ${DEFAULT_SKILL_URL}: ${err instanceof Error ? err.message : String(err)}`);
      if (existsSync(skillPath)) {
        console.error('Falling back to bundled snapshot');
        process.stdout.write(readFileSync(skillPath, 'utf-8'));
        return 0;
      }
      console.error('No bundled snapshot available. Install the latest @hebrah/cli or check your network.');
      return 1;
    }
  }

  process.stdout.write(readFileSync(skillPath, 'utf-8'));
  return 0;
}