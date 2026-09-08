// Argv helper — extracts the first non-flag positional and the full flag
// argv slice from the forwarded `options` object.
//
// Background: the top-level parser in src/index.ts uses `strict: false`
// so unknown flags flow through, but any flag with a string value (like
// --sql "SELECT 1") has its value silently hoisted into `positionals` by
// the top-level parser. To avoid this, index.ts forwards the raw argv
// slice as `options._argv` and each command re-parses that instead of
// the polluted `args` parameter.

export function getPositional(args: string[], options: Record<string, unknown>): string | undefined {
  const argv = (options._argv as string[] | undefined) ?? args;
  return argv.find((a) => !a.startsWith('-') && !a.includes('='));
}

export function getArgv(options: Record<string, unknown>, fallback: string[] = []): string[] {
  return (options._argv as string[] | undefined) ?? fallback;
}