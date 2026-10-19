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

// Strip dangerous terminal escape sequences (OSC 52 clipboard hijack, OSC 8 hyperlinks,
// 8-bit C1 equivalents, cursor repositioning, window title injection) and raw control characters.
const OSC_OR_DCS_RE =
  /(?:\x1b(?:\][\s\S]*?(?:\x07|\x1b\\|\x9c)|[PX^_][\s\S]*?(?:\x07|\x1b\\|\x9c))|[\x90\x98\x9d\x9e\x9f][\s\S]*?(?:\x07|\x1b\\|\x9c))/g;
const CSI_RE = /(?:\x1b\[|\x9b)[0-9;?]*[ -/]*[@-~]/g;
const NON_SGR_CSI_RE = /(?:\x1b\[|\x9b)(?![0-9;]*m)[0-9;?]*[ -/]*[@-~]/g;
const BARE_ESC_RE = /\x1b(?!\[[0-9;]*m)/g;
const RAW_CTRL_RE = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/g;
const RAW_CTRL_NO_ESC_RE = /[\x00-\x08\x0b-\x1a\x1c-\x1f\x7f-\x9f]/g;

export function sanitizeTerminalText(raw: string): string {
  return String(raw)
    .replace(OSC_OR_DCS_RE, '')
    .replace(CSI_RE, '')
    .replace(RAW_CTRL_RE, '');
}

export function sanitizeAllowingSgr(raw: string): string {
  return String(raw)
    .replace(OSC_OR_DCS_RE, '')
    .replace(NON_SGR_CSI_RE, '')
    .replace(BARE_ESC_RE, '')
    .replace(RAW_CTRL_NO_ESC_RE, '');
}

function colorize(s: string, color: keyof typeof COLORS): string {
  const safe = sanitizeAllowingSgr(s);
  if (process.env.NO_COLOR || !process.stdout.isTTY) return safe;
  return `${COLORS[color]}${safe}${COLORS.reset}`;
}

const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/\bhb_(?:live|test|pat|conn|claim)_[A-Za-z0-9_-]{6,}\b(?!\.\.\.)/g, '[REDACTED_HEBRAH_TOKEN]'],
  [/\benc:v1:[A-Za-z0-9+/=_:-]+/g, 'enc:v1:[REDACTED]'],
  [/(PrivateKey[ \t]*=[ \t]*)(?!\s*(?:<redacted|\[REDACTED))[^\r\n"\\]+/gi, '$1[REDACTED]'],
  [/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1[REDACTED]'],
  [/(\b[a-z][a-z0-9+.-]*:\/\/[^:\s/@]+:)([^\s/]+)(@)/gi, '$1[REDACTED]$3']
];

export function redactSecrets(raw: string): string {
  let out = String(raw);
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  return out;
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
  const serialized = redactSecrets(JSON.stringify(data, null, 2) ?? 'null');
  const safeJson = serialized.replace(/[\x7f-\x9f]/g, (ch) =>
    `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`
  );
  console.log(safeJson);
}

const SGR_RE = /\x1b\[[0-9;]*m/g;

export function visibleLength(s: string): number {
  return s.replace(SGR_RE, '').length;
}

function padVisualEnd(s: string, width: number): string {
  const pad = Math.max(0, width - visibleLength(s));
  return s + ' '.repeat(pad);
}

export function table(headers: string[], rows: string[][]): void {
  if (rows.length === 0) {
    console.log(dim('(no rows)'));
    return;
  }
  const safeHeaders = headers.map((h) => redactSecrets(sanitizeTerminalText(h)));
  const safeRows = rows.map((r) =>
    r.map((cell) => redactSecrets(sanitizeAllowingSgr(cell ?? '')))
  );
  // Calculate column widths based on visible length (excluding SGR color codes)
  const widths = safeHeaders.map((h, i) =>
    Math.max(visibleLength(h), ...safeRows.map((r) => visibleLength(r[i] ?? '')))
  );

  // Header
  const headerLine = safeHeaders.map((h, i) => bold(padVisualEnd(h, widths[i]))).join('  ');
  console.log(headerLine);

  // Separator
  console.log(dim(widths.map((w) => '─'.repeat(w)).join('  ')));

  // Rows
  for (const row of safeRows) {
    const line = row.map((cell, i) => padVisualEnd(cell ?? '', widths[i])).join('  ');
    console.log(line);
  }
}

export function kv(pairs: Array<[string, string]>, labelColor: keyof typeof COLORS = 'cyan'): void {
  const maxLabel = Math.max(...pairs.map(([k]) => sanitizeTerminalText(k).length));
  for (const [key, value] of pairs) {
    const paddedKey = sanitizeTerminalText(key).padEnd(maxLabel);
    // Preserve intentional SGR color sequences emitted by CLI commands while stripping OSC/CSI/control chars
    const safeVal = redactSecrets(sanitizeAllowingSgr(String(value)));
    console.log(`${colorize(paddedKey, labelColor)}  ${safeVal}`);
  }
}

export function success(message: string): void {
  console.log(`${green('✓')} ${redactSecrets(sanitizeAllowingSgr(message))}`);
}

export function warn(message: string): void {
  console.error(`${yellow('!')} ${redactSecrets(sanitizeAllowingSgr(message))}`);
}

export function error(message: string): void {
  console.error(`${red('✗')} ${redactSecrets(sanitizeAllowingSgr(message))}`);
}

export function info(message: string): void {
  console.log(`${blue('ℹ')} ${redactSecrets(sanitizeAllowingSgr(message))}`);
}

/**
 * Standardized CLI error formatter & exit-code mapper:
 * - Prints the redacted/sanitized error message (with optional prefix) and any `suggestion` hint.
 * - Returns semantic exit codes: 2 (401 Auth), 3 (403 Scope/Forbidden), 4 (other ApiError / TimeoutError), 1 (general).
 */
export function handleCommandError(err: unknown, prefix?: string): number {
  const rawMessage = err instanceof Error ? err.message : String(err);
  error(prefix ? `${prefix}: ${rawMessage}` : rawMessage);

  if (typeof err === 'object' && err !== null) {
    const suggestion = (err as { suggestion?: unknown }).suggestion;
    if (typeof suggestion === 'string' && suggestion.length > 0) {
      info(suggestion);
    }
    const statusCode = (err as { statusCode?: unknown }).statusCode;
    if (typeof statusCode === 'number') {
      if (statusCode === 401) return 2;
      if (statusCode === 403) return 3;
      if (statusCode === 402) return 5;
      return 4;
    }
    if ((err as { name?: unknown }).name === 'TimeoutError') {
      return 4;
    }
  }
  return 1;
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