// Output formatting — pretty (default), table, or JSON (--json flag).
//
// Wave 1 ships 3 formatters:
//   - json:    single-line JSON for agents
//   - pretty:  colored, aligned text for humans
//   - table:   aligned columns with header

const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

function colorize(s: string, color: keyof typeof COLORS): string {
  if (process.env.NO_COLOR || !process.stdout.isTTY) return s;
  return `${COLORS[color]}${s}${COLORS.reset}`;
}

export function dim(s: string): string { return colorize(s, 'dim'); }
export function bold(s: string): string { return colorize(s, 'bold'); }
export function green(s: string): string { return colorize(s, 'green'); }
export function yellow(s: string): string { return colorize(s, 'yellow'); }
export function red(s: string): string { return colorize(s, 'red'); }
export function blue(s: string): string { return colorize(s, 'blue'); }
export function cyan(s: string): string { return colorize(s, 'cyan'); }
export function gray(s: string): string { return colorize(s, 'gray'); }

export function json(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

export function table(headers: string[], rows: string[][]): void {
  if (rows.length === 0) {
    console.log(dim('(no rows)'));
    return;
  }
  // Calculate column widths
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length))
  );

  // Header
  const headerLine = headers.map((h, i) => bold(h.padEnd(widths[i]))).join('  ');
  console.log(headerLine);

  // Separator
  console.log(dim(widths.map((w) => '─'.repeat(w)).join('  ')));

  // Rows
  for (const row of rows) {
    const line = row.map((cell, i) => (cell ?? '').padEnd(widths[i])).join('  ');
    console.log(line);
  }
}

export function kv(pairs: Array<[string, string]>, labelColor: keyof typeof COLORS = 'cyan'): void {
  const maxLabel = Math.max(...pairs.map(([k]) => k.length));
  for (const [key, value] of pairs) {
    const paddedKey = key.padEnd(maxLabel);
    console.log(`${colorize(paddedKey, labelColor)}  ${value}`);
  }
}

export function success(message: string): void {
  console.log(`${green('✓')} ${message}`);
}

export function warn(message: string): void {
  console.error(`${yellow('!')} ${message}`);
}

export function error(message: string): void {
  console.error(`${red('✗')} ${message}`);
}

export function info(message: string): void {
  console.log(`${blue('ℹ')} ${message}`);
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

export function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(4)}`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.floor(seconds / 86400)}d`;
}