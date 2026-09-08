#!/usr/bin/env node
// Hebrah CLI — main entry point.
// Wave 1 command surface (12 commands):
//   signup, login, logout, whoami, usage, discover, inspect,
//   connect, list, status, revoke, query, audit, audit verify,
//   audit export

import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PACKAGE_VERSION = JSON.parse(
  readFileSync(join(__dirname, '..', 'package.json'), 'utf-8')
).version;

// Command registry (Wave 1)
const COMMANDS: Record<string, CommandDescriptor> = {
  signup: { description: 'Create a new agent account', handler: () => import('./commands/signup.js') },
  login: { description: 'Load existing credentials', handler: () => import('./commands/login.js') },
  logout: { description: 'Remove local credentials', handler: () => import('./commands/logout.js') },
  whoami: { description: 'Show account info + balance', handler: () => import('./commands/whoami.js') },
  usage: { description: 'Show metering for current period', handler: () => import('./commands/usage.js') },
  discover: { description: 'List available targets', handler: () => import('./commands/discover.js') },
  inspect: { description: 'Show scope grammar for a target', handler: () => import('./commands/inspect.js') },
  packs: { description: 'List connector packs', handler: () => import('./commands/packs.js') },
  connect: { description: 'Open a scoped connection', handler: () => import('./commands/connect.js') },
  list: { description: 'List active connections', handler: () => import('./commands/list.js') },
  status: { description: 'Show connection status', handler: () => import('./commands/status.js') },
  revoke: { description: 'Close a connection', handler: () => import('./commands/revoke.js') },
  query: { description: 'Execute query through connection', handler: () => import('./commands/query.js') },
  audit: { description: 'Show / verify / export audit events', handler: () => import('./commands/audit.js') },
  topup: { description: 'Add credit via Stripe Checkout', handler: () => import('./commands/topup.js') },
  skill: { description: 'Show the SKILL.md', handler: async () => (await import('./commands/skill.js')) as { default: (args: string[], options: Record<string, unknown>) => Promise<number> } },
  version: { description: 'Show version', handler: async () => { console.log(`hebrah ${PACKAGE_VERSION}`); } },
  help: { description: 'Show help', handler: async () => { showHelp(); } }
};

interface CommandDescriptor {
  description: string;
  // Either lazy-loads a TS module with a default export OR returns void directly.
  // The lazy-load path is used by feature commands; the void path is used by
  // built-ins like `version` and `help` that don't need user args/options.
  handler: (() => Promise<{ default: (args: string[], options: Record<string, unknown>) => Promise<number> }>) | (() => Promise<void>);
}

async function main(): Promise<number> {
  // Only consume truly global flags at the top level. Per-command flags
  // (--json, --sql, --scopes, etc.) must NOT be consumed here, because
  // the top-level parser would treat unknown flags as booleans and silently
  // drop their string values. Each command re-parses its own argv slice.
  const { positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    strict: false,
    options: {
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', short: 'v', default: false },
      debug: { type: 'boolean', default: false }
    }
  });

  const cmd = positionals[0] ?? 'help';
  const debug = process.argv.includes('--debug');

  if (process.argv.includes('-v') || process.argv.includes('--version')) {
    console.log(`hebrah ${PACKAGE_VERSION}`);
    return 0;
  }

  if (cmd === 'help' || process.argv.includes('-h') || process.argv.includes('--help')) {
    showHelp();
    return 0;
  }

  const descriptor = COMMANDS[cmd];
  if (!descriptor) {
    console.error(`hebrah: unknown command "${cmd}"`);
    console.error(`Run "hebrah help" for usage.`);
    return 1;
  }

  try {
    const result = await descriptor.handler();
    if (result === undefined) return 0;  // void-returning built-in (version, help)
    // Pass positionals.slice(1) as positional args AND the original argv
    // slice (after the command name) so per-command parseArgs sees all
    // flags intact. The top-level parser with strict:false drops unknown
    // flag values, so we must hand the command the raw argv.
    const cmdArgv = process.argv.slice(2 + 1); // skip 'node', 'bin/hebrah'
    return await result.default(positionals.slice(1), { _command: cmd, debug, _argv: cmdArgv });
  } catch (err: any) {
    if (debug) {
      console.error(err.stack);
    } else {
      console.error(`hebrah: ${err.message ?? 'unknown error'}`);
      if (err.suggestion) {
        console.error(`Hint: ${err.suggestion}`);
      }
    }
    return 4;
  }
}

function showHelp(): void {
  console.log(`hebrah ${PACKAGE_VERSION} — the data layer for AI agents

Usage:
  hebrah <command> [options]

Commands:
  Account:
    signup              Create a new agent account
    login               Load existing credentials
    logout              Remove local credentials
    whoami              Show account info + balance
    usage               Show metering for current period

  Discovery:
    discover            List available targets
    inspect <target>    Show scope grammar for a target
    packs               List connector packs

  Connection lifecycle:
    connect <target>    Open a scoped connection
    list                List active connections
    status <conn>       Show connection status
    revoke <conn>       Close a connection

  Query:
    query <conn>        Execute query through connection

  Audit:
    audit <conn>        Show audit events
    audit verify <conn> Verify hash chain
    audit export <conn> Export hash-chained audit log

  Billing:
    topup               Add credit via Stripe Checkout

  Help:
    skill               Show the SKILL.md
    help                Show this help
    version             Show version

Options:
  --json                 Output as JSON
  --debug                Show stack traces on errors
  -h, --help             Show help
  -v, --version          Show version

Docs:    https://hebrah.com/docs
SKILL:   https://hebrah.com/SKILL.md
Pricing: https://hebrah.com/pricing
`);
}

main().then((code) => process.exit(code)).catch((err) => {
  console.error('hebrah: fatal error');
  console.error(err);
  process.exit(4);
});