/**
 * `hebrah mcp` — Configure, inspect, and verify the Hebrah Hosted MCP Server
 * across Claude Code, Cursor, Google Antigravity, Windsurf, and VS Code.
 *
 * Designed to eliminate common MCP setup pitfalls:
 *   1. Always configures Claude Code at `user` scope (`~/.claude.json` top-level `mcpServers`)
 *      so the server loads in every project directory instead of only `~` (`local` scope).
 *   2. Automatically cleans up stale or tokenless local-scope overrides in `~/.claude.json`
 *      (`projects[*].mcpServers.hebrah`) that would otherwise shadow user scope or trigger
 *      `Dynamic Client Registration rejected (HTTP 404)`.
 *   3. Reads saved CLI credentials (`~/.hebrah/credentials`, `hb_conn_*` or `hb_pat_*`) directly
 *      on disk so tokens never need to be pasted into AI chat transcripts.
 *   4. `hebrah mcp status` redacts all Bearer tokens (`hb_conn_abcdef...`) so checking status
 *      inside an agent session never leaks secrets into transcripts (unlike `claude mcp get`).
 */

import { parseArgs } from 'node:util';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  chmodSync
} from 'node:fs';
import { dirname, join, resolve as resolvePath } from 'node:path';
import { homedir } from 'node:os';
import { randomBytes } from 'node:crypto';
import {
  loadCredentials,
  isValidApiKeyFormat,
  maskApiKey
} from '../config/credentials.js';
import { safeId, validateApiBaseUrl } from '../api/client.js';
import {
  bold,
  cyan,
  error,
  green,
  info,
  json,
  kv,
  redactSecrets,
  sanitizeTerminalText,
  success,
  table,
  warn,
  yellow
} from '../output/format.js';
import { getArgv } from '../util/args.js';
import { scrubProcessArgvSecret } from './login.js';

export type McpClientTarget = 'claude' | 'cursor' | 'antigravity' | 'windsurf' | 'vscode';
export type McpScope = 'user' | 'project';

export interface McpInstallOptions {
  client?: string;
  scope?: McpScope;
  mcpUrl?: string;
  envId?: string;
  serverName?: string;
  apiKey?: string;
  homeDir?: string;
  cwd?: string;
}

export interface McpClientInstallResult {
  client: McpClientTarget;
  label: string;
  scope: McpScope;
  configPath: string;
  serverName: string;
  endpointUrl: string;
  keyPrefix: string;
  envId?: string;
  cleanedLocalOverrides?: string[];
}

export interface McpInspectionEntry {
  client: McpClientTarget;
  label: string;
  scope: 'user' | 'local' | 'project';
  configPath: string;
  projectScopePath?: string;
  endpointUrl: string;
  hasBearerToken: boolean;
  validTokenFormat: boolean;
  keyPrefix: string;
  envId?: string;
  warnings: string[];
}

const DEFAULT_MCP_URL = 'https://mcp.hebrah.com/mcp';
const STAGING_MCP_URL = 'https://mcp-staging.hebrah.com/mcp';
const LOCAL_MCP_URL = 'http://localhost:3021/mcp';
const MAX_CONFIG_FILE_BYTES = 10 * 1024 * 1024; // 10 MB safety ceiling for ~/.claude.json

function assertNotSymlink(targetPath: string): void {
  try {
    const st = lstatSync(targetPath);
    if (st.isSymbolicLink()) {
      throw new Error(`Security error: refusing to access symbolic link at ${targetPath}`);
    }
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return;
    throw err;
  }
}

function readJsonFileSafe(filePath: string): Record<string, unknown> {
  assertNotSymlink(filePath);
  if (!existsSync(filePath)) return {};
  const st = lstatSync(filePath);
  if (!st.isFile()) {
    throw new Error(`Security error: ${filePath} is not a regular file`);
  }
  if (st.size > MAX_CONFIG_FILE_BYTES) {
    throw new Error(`Config file ${filePath} exceeds maximum allowed size (${MAX_CONFIG_FILE_BYTES} bytes)`);
  }
  const raw = readFileSync(filePath, 'utf-8').trim();
  if (!raw) return {};
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Config file ${filePath} does not contain a top-level JSON object`);
  }
  return parsed as Record<string, unknown>;
}

function writeJsonFileAtomic(filePath: string, data: Record<string, unknown>): void {
  const parentDir = dirname(filePath);
  assertNotSymlink(parentDir);
  mkdirSync(parentDir, { recursive: true, mode: 0o700 });
  assertNotSymlink(filePath);

  const tmpPath = `${filePath}.tmp.${process.pid}.${randomBytes(4).toString('hex')}`;
  try {
    const serialized = `${JSON.stringify(data, null, 2)}\n`;
    writeFileSync(tmpPath, serialized, { encoding: 'utf-8', mode: 0o600 });
    if (process.platform !== 'win32') {
      try {
        chmodSync(tmpPath, 0o600);
      } catch {
        // ignore on filesystems that do not support chmod
      }
    }
    renameSync(tmpPath, filePath);
    if (process.platform !== 'win32') {
      try {
        chmodSync(filePath, 0o600);
      } catch {
        // ignore
      }
    }
  } catch (err) {
    try {
      if (existsSync(tmpPath)) unlinkSync(tmpPath);
    } catch {
      // ignore cleanup error
    }
    throw err;
  }
}

export function normalizeMcpEndpointUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim().replace(/\/+$/, '');
  const withPath = trimmed.endsWith('/mcp') ? trimmed : `${trimmed}/mcp`;
  const baseValidated = validateApiBaseUrl(withPath.replace(/\/mcp$/, ''));
  const parsed = new URL(`${baseValidated}/mcp`);
  if (parsed.hostname === '0.0.0.0') {
    parsed.hostname = 'localhost';
  }
  return parsed.toString().replace(/\/+$/, '');
}

export function resolveMcpEndpoint(explicitMcpUrl?: string): string {
  if (explicitMcpUrl) {
    return normalizeMcpEndpointUrl(explicitMcpUrl);
  }
  if (process.env.HEBRAH_MCP_URL) {
    return normalizeMcpEndpointUrl(process.env.HEBRAH_MCP_URL);
  }
  const creds = loadCredentials();
  if (creds?.mcpEndpointUrl) {
    try {
      return normalizeMcpEndpointUrl(creds.mcpEndpointUrl);
    } catch {
      // fall through to inference
    }
  }
  const apiUrl = process.env.HEBRAH_API_URL ?? creds?.apiUrl ?? '';
  if (apiUrl.includes('localhost') || apiUrl.includes('127.0.0.1')) {
    return LOCAL_MCP_URL;
  }
  if (apiUrl.includes('-staging-api-') || apiUrl.includes('api-staging.hebrah.com')) {
    if (apiUrl.includes('-staging-api-')) {
      return normalizeMcpEndpointUrl(apiUrl.replace('-staging-api-', '-staging-mcp-'));
    }
    return STAGING_MCP_URL;
  }
  return DEFAULT_MCP_URL;
}

export function resolveTargets(
  clientFlag: string | undefined,
  scope: McpScope,
  homeDir: string
): McpClientTarget[] {
  const normalized = (clientFlag ?? 'auto').trim().toLowerCase();
  if (normalized === 'all') {
    return scope === 'project'
      ? ['claude', 'cursor', 'vscode']
      : ['claude', 'cursor', 'antigravity', 'windsurf'];
  }
  if (normalized === 'auto') {
    if (scope === 'project') {
      return ['claude', 'cursor', 'vscode'];
    }
    const targets: McpClientTarget[] = ['claude', 'cursor'];
    if (existsSync(join(homeDir, '.gemini', 'antigravity'))) {
      targets.push('antigravity');
    }
    if (existsSync(join(homeDir, '.codeium', 'windsurf'))) {
      targets.push('windsurf');
    }
    return targets;
  }

  const parts = normalized.split(',').map((p) => p.trim()).filter(Boolean);
  const targets: McpClientTarget[] = [];
  for (const part of parts) {
    if (part === 'claude' || part === 'claude-code' || part === 'claudecode') {
      targets.push('claude');
    } else if (part === 'cursor') {
      targets.push('cursor');
    } else if (part === 'antigravity' || part === 'gemini') {
      targets.push('antigravity');
    } else if (part === 'windsurf' || part === 'codeium') {
      targets.push('windsurf');
    } else if (part === 'vscode' || part === 'vs-code') {
      targets.push('vscode');
    } else {
      throw new Error(
        `Unknown MCP client "${part}". Supported values: auto, all, claude, cursor, antigravity, windsurf, vscode.`
      );
    }
  }
  return Array.from(new Set(targets));
}

export function installMcpForClient(opts: {
  client: McpClientTarget;
  scope: McpScope;
  endpointUrl: string;
  apiKey: string;
  envId?: string;
  serverName: string;
  homeDir: string;
  cwd: string;
}): McpClientInstallResult {
  const { client, scope, endpointUrl, apiKey, envId, serverName, homeDir, cwd } = opts;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${apiKey}`
  };
  if (envId) {
    headers['X-Hebrah-Environment-Id'] = envId;
  }

  const keyPrefix = maskApiKey(apiKey);

  if (client === 'claude') {
    if (scope === 'project') {
      const configPath = join(cwd, '.mcp.json');
      const doc = readJsonFileSafe(configPath);
      const mcpServers =
        doc.mcpServers && typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers)
          ? (doc.mcpServers as Record<string, unknown>)
          : {};
      mcpServers[serverName] = {
        type: 'http',
        url: endpointUrl,
        headers
      };
      doc.mcpServers = mcpServers;
      writeJsonFileAtomic(configPath, doc);
      return {
        client,
        label: 'Claude Code (project .mcp.json)',
        scope: 'project',
        configPath,
        serverName,
        endpointUrl,
        keyPrefix,
        envId
      };
    }

    const configPath = join(homeDir, '.claude.json');
    const doc = readJsonFileSafe(configPath);
    const mcpServers =
      doc.mcpServers && typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers)
        ? (doc.mcpServers as Record<string, unknown>)
        : {};
    mcpServers[serverName] = {
      type: 'http',
      url: endpointUrl,
      headers
    };
    doc.mcpServers = mcpServers;

    // Clean up any local-scope `projects[*].mcpServers[serverName]` entries so they
    // cannot shadow the user-scope entry or fail with HTTP 404 from missing headers.
    const cleanedLocalOverrides: string[] = [];
    if (doc.projects && typeof doc.projects === 'object' && !Array.isArray(doc.projects)) {
      const projects = doc.projects as Record<string, unknown>;
      for (const [projPath, projVal] of Object.entries(projects)) {
        if (!projVal || typeof projVal !== 'object' || Array.isArray(projVal)) continue;
        const projObj = projVal as Record<string, unknown>;
        if (
          projObj.mcpServers &&
          typeof projObj.mcpServers === 'object' &&
          !Array.isArray(projObj.mcpServers)
        ) {
          const projServers = projObj.mcpServers as Record<string, unknown>;
          if (serverName in projServers) {
            delete projServers[serverName];
            cleanedLocalOverrides.push(projPath);
          }
        }
      }
    }

    writeJsonFileAtomic(configPath, doc);
    return {
      client,
      label: 'Claude Code (user scope)',
      scope: 'user',
      configPath,
      serverName,
      endpointUrl,
      keyPrefix,
      envId,
      cleanedLocalOverrides
    };
  }

  if (client === 'cursor') {
    const configPath =
      scope === 'project'
        ? join(cwd, '.cursor', 'mcp.json')
        : join(homeDir, '.cursor', 'mcp.json');
    const doc = readJsonFileSafe(configPath);
    const mcpServers =
      doc.mcpServers && typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers)
        ? (doc.mcpServers as Record<string, unknown>)
        : {};
    mcpServers[serverName] = {
      type: 'http',
      url: endpointUrl,
      headers
    };
    doc.mcpServers = mcpServers;
    writeJsonFileAtomic(configPath, doc);
    return {
      client,
      label: scope === 'project' ? 'Cursor (project)' : 'Cursor (user scope)',
      scope,
      configPath,
      serverName,
      endpointUrl,
      keyPrefix,
      envId
    };
  }

  if (client === 'antigravity') {
    const configPath = join(homeDir, '.gemini', 'antigravity', 'mcp_config.json');
    const doc = readJsonFileSafe(configPath);
    const mcpServers =
      doc.mcpServers && typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers)
        ? (doc.mcpServers as Record<string, unknown>)
        : {};
    mcpServers[serverName] = {
      serverUrl: endpointUrl,
      headers
    };
    doc.mcpServers = mcpServers;
    writeJsonFileAtomic(configPath, doc);
    return {
      client,
      label: 'Google Antigravity',
      scope: 'user',
      configPath,
      serverName,
      endpointUrl,
      keyPrefix,
      envId
    };
  }

  if (client === 'windsurf') {
    const configPath = join(homeDir, '.codeium', 'windsurf', 'mcp_config.json');
    const doc = readJsonFileSafe(configPath);
    const mcpServers =
      doc.mcpServers && typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers)
        ? (doc.mcpServers as Record<string, unknown>)
        : {};
    mcpServers[serverName] = {
      serverUrl: endpointUrl,
      headers
    };
    doc.mcpServers = mcpServers;
    writeJsonFileAtomic(configPath, doc);
    return {
      client,
      label: 'Windsurf',
      scope: 'user',
      configPath,
      serverName,
      endpointUrl,
      keyPrefix,
      envId
    };
  }

  // vscode
  const configPath = join(cwd, '.vscode', 'mcp.json');
  const doc = readJsonFileSafe(configPath);
  const servers =
    doc.servers && typeof doc.servers === 'object' && !Array.isArray(doc.servers)
      ? (doc.servers as Record<string, unknown>)
      : {};
  servers[serverName] = {
    type: 'http',
    url: endpointUrl,
    headers
  };
  doc.servers = servers;
  writeJsonFileAtomic(configPath, doc);
  return {
    client: 'vscode',
    label: 'VS Code (.vscode/mcp.json)',
    scope: 'project',
    configPath,
    serverName,
    endpointUrl,
    keyPrefix,
    envId
  };
}

function parseServerBlock(
  rawEntry: unknown,
  meta: {
    client: McpClientTarget;
    label: string;
    scope: 'user' | 'local' | 'project';
    configPath: string;
    projectScopePath?: string;
    hasUserScopeEntry?: boolean;
  }
): McpInspectionEntry | null {
  if (!rawEntry || typeof rawEntry !== 'object' || Array.isArray(rawEntry)) return null;
  const obj = rawEntry as Record<string, unknown>;
  const endpointUrl = String(obj.url ?? obj.serverUrl ?? '').trim();
  const headers =
    obj.headers && typeof obj.headers === 'object' && !Array.isArray(obj.headers)
      ? (obj.headers as Record<string, unknown>)
      : {};
  const authVal = String(headers.Authorization ?? headers.authorization ?? '').trim();
  const bearerMatch = authVal.match(/^Bearer\s+(.+)$/i);
  const rawToken = bearerMatch?.[1]?.trim() ?? '';
  const hasBearerToken = rawToken.length > 0;
  const validTokenFormat = isValidApiKeyFormat(rawToken);
  const keyPrefix = hasBearerToken ? maskApiKey(rawToken) : '(missing)';
  const envId =
    typeof headers['X-Hebrah-Environment-Id'] === 'string'
      ? headers['X-Hebrah-Environment-Id']
      : undefined;

  const warnings: string[] = [];
  if (!hasBearerToken) {
    warnings.push(
      'Missing Authorization: Bearer header (causes HTTP 401 / Dynamic Client Registration 404 in Claude Code). Run `hebrah mcp install` to fix.'
    );
  } else if (!validTokenFormat) {
    warnings.push(
      'Bearer token is not a recognized hb_conn_*, hb_pat_*, hb_live_*, or hb_test_* key (may be a placeholder).'
    );
  }

  if (meta.scope === 'local') {
    warnings.push(
      `Saved at Claude Code local scope for "${meta.projectScopePath ?? ''}" only — sessions in other folders will not load it${meta.hasUserScopeEntry ? ' and it may shadow your user-scope config' : ''}. Run \`hebrah mcp install\` to promote to user scope.`
    );
  }

  return {
    client: meta.client,
    label: meta.label,
    scope: meta.scope,
    configPath: meta.configPath,
    projectScopePath: meta.projectScopePath,
    endpointUrl: endpointUrl || '(not set)',
    hasBearerToken,
    validTokenFormat,
    keyPrefix,
    envId,
    warnings
  };
}

export function inspectConfiguredMcpClients(opts: {
  serverName?: string;
  homeDir?: string;
  cwd?: string;
}): McpInspectionEntry[] {
  const serverName = opts.serverName ?? 'hebrah';
  const homeDir = opts.homeDir ?? homedir();
  const cwd = opts.cwd ?? process.cwd();
  const entries: McpInspectionEntry[] = [];

  // 1. Claude Code ~/.claude.json (both user scope and per-folder local scope)
  const claudePath = join(homeDir, '.claude.json');
  if (existsSync(claudePath)) {
    try {
      const doc = readJsonFileSafe(claudePath);
      const userServers =
        doc.mcpServers && typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers)
          ? (doc.mcpServers as Record<string, unknown>)
          : {};
      const hasUserScope = Boolean(userServers[serverName]);
      if (userServers[serverName]) {
        const parsed = parseServerBlock(userServers[serverName], {
          client: 'claude',
          label: 'Claude Code',
          scope: 'user',
          configPath: claudePath
        });
        if (parsed) entries.push(parsed);
      }

      if (doc.projects && typeof doc.projects === 'object' && !Array.isArray(doc.projects)) {
        const projects = doc.projects as Record<string, unknown>;
        for (const [projPath, projVal] of Object.entries(projects)) {
          if (!projVal || typeof projVal !== 'object' || Array.isArray(projVal)) continue;
          const projObj = projVal as Record<string, unknown>;
          const projServers =
            projObj.mcpServers &&
            typeof projObj.mcpServers === 'object' &&
            !Array.isArray(projObj.mcpServers)
              ? (projObj.mcpServers as Record<string, unknown>)
              : {};
          if (projServers[serverName]) {
            const parsed = parseServerBlock(projServers[serverName], {
              client: 'claude',
              label: `Claude Code (local: ${projPath})`,
              scope: 'local',
              configPath: claudePath,
              projectScopePath: projPath,
              hasUserScopeEntry: hasUserScope
            });
            if (parsed) entries.push(parsed);
          }
        }
      }
    } catch {
      // ignore unreadable file
    }
  }

  // 2. Project .mcp.json
  const projectMcpJson = join(cwd, '.mcp.json');
  if (existsSync(projectMcpJson)) {
    try {
      const doc = readJsonFileSafe(projectMcpJson);
      const servers =
        doc.mcpServers && typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers)
          ? (doc.mcpServers as Record<string, unknown>)
          : {};
      if (servers[serverName]) {
        const parsed = parseServerBlock(servers[serverName], {
          client: 'claude',
          label: 'Claude Code (.mcp.json)',
          scope: 'project',
          configPath: projectMcpJson
        });
        if (parsed) entries.push(parsed);
      }
    } catch {
      // ignore
    }
  }

  // 3. Cursor user scope (~/.cursor/mcp.json) & project (.cursor/mcp.json)
  const cursorUserPath = join(homeDir, '.cursor', 'mcp.json');
  if (existsSync(cursorUserPath)) {
    try {
      const doc = readJsonFileSafe(cursorUserPath);
      const servers =
        doc.mcpServers && typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers)
          ? (doc.mcpServers as Record<string, unknown>)
          : {};
      if (servers[serverName]) {
        const parsed = parseServerBlock(servers[serverName], {
          client: 'cursor',
          label: 'Cursor',
          scope: 'user',
          configPath: cursorUserPath
        });
        if (parsed) entries.push(parsed);
      }
    } catch {
      // ignore
    }
  }

  const cursorProjectPath = join(cwd, '.cursor', 'mcp.json');
  if (existsSync(cursorProjectPath) && resolvePath(cursorProjectPath) !== resolvePath(cursorUserPath)) {
    try {
      const doc = readJsonFileSafe(cursorProjectPath);
      const servers =
        doc.mcpServers && typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers)
          ? (doc.mcpServers as Record<string, unknown>)
          : {};
      if (servers[serverName]) {
        const parsed = parseServerBlock(servers[serverName], {
          client: 'cursor',
          label: 'Cursor (.cursor/mcp.json)',
          scope: 'project',
          configPath: cursorProjectPath
        });
        if (parsed) entries.push(parsed);
      }
    } catch {
      // ignore
    }
  }

  // 4. Google Antigravity
  const antigravityPath = join(homeDir, '.gemini', 'antigravity', 'mcp_config.json');
  if (existsSync(antigravityPath)) {
    try {
      const doc = readJsonFileSafe(antigravityPath);
      const servers =
        doc.mcpServers && typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers)
          ? (doc.mcpServers as Record<string, unknown>)
          : {};
      if (servers[serverName]) {
        const parsed = parseServerBlock(servers[serverName], {
          client: 'antigravity',
          label: 'Google Antigravity',
          scope: 'user',
          configPath: antigravityPath
        });
        if (parsed) entries.push(parsed);
      }
    } catch {
      // ignore
    }
  }

  // 5. Windsurf
  const windsurfPath = join(homeDir, '.codeium', 'windsurf', 'mcp_config.json');
  if (existsSync(windsurfPath)) {
    try {
      const doc = readJsonFileSafe(windsurfPath);
      const servers =
        doc.mcpServers && typeof doc.mcpServers === 'object' && !Array.isArray(doc.mcpServers)
          ? (doc.mcpServers as Record<string, unknown>)
          : {};
      if (servers[serverName]) {
        const parsed = parseServerBlock(servers[serverName], {
          client: 'windsurf',
          label: 'Windsurf',
          scope: 'user',
          configPath: windsurfPath
        });
        if (parsed) entries.push(parsed);
      }
    } catch {
      // ignore
    }
  }

  // 6. VS Code (.vscode/mcp.json)
  const vscodePath = join(cwd, '.vscode', 'mcp.json');
  if (existsSync(vscodePath)) {
    try {
      const doc = readJsonFileSafe(vscodePath);
      const servers =
        doc.servers && typeof doc.servers === 'object' && !Array.isArray(doc.servers)
          ? (doc.servers as Record<string, unknown>)
          : {};
      if (servers[serverName]) {
        const parsed = parseServerBlock(servers[serverName], {
          client: 'vscode',
          label: 'VS Code (.vscode/mcp.json)',
          scope: 'project',
          configPath: vscodePath
        });
        if (parsed) entries.push(parsed);
      }
    } catch {
      // ignore
    }
  }

  return entries;
}

export function removeMcpFromClients(opts: {
  serverName?: string;
  homeDir?: string;
  cwd?: string;
}): string[] {
  const serverName = opts.serverName ?? 'hebrah';
  const homeDir = opts.homeDir ?? homedir();
  const cwd = opts.cwd ?? process.cwd();
  const removedFrom: string[] = [];

  const candidateFiles: Array<{ path: string; rootKey: 'mcpServers' | 'servers'; cleanClaudeProjects?: boolean }> = [
    { path: join(homeDir, '.claude.json'), rootKey: 'mcpServers', cleanClaudeProjects: true },
    { path: join(cwd, '.mcp.json'), rootKey: 'mcpServers' },
    { path: join(homeDir, '.cursor', 'mcp.json'), rootKey: 'mcpServers' },
    { path: join(cwd, '.cursor', 'mcp.json'), rootKey: 'mcpServers' },
    { path: join(homeDir, '.gemini', 'antigravity', 'mcp_config.json'), rootKey: 'mcpServers' },
    { path: join(homeDir, '.codeium', 'windsurf', 'mcp_config.json'), rootKey: 'mcpServers' },
    { path: join(cwd, '.vscode', 'mcp.json'), rootKey: 'servers' }
  ];

  const seenPaths = new Set<string>();
  for (const item of candidateFiles) {
    const abs = resolvePath(item.path);
    if (seenPaths.has(abs) || !existsSync(abs)) continue;
    seenPaths.add(abs);
    try {
      const doc = readJsonFileSafe(abs);
      let modified = false;
      const mapObj = doc[item.rootKey];
      if (mapObj && typeof mapObj === 'object' && !Array.isArray(mapObj)) {
        const servers = mapObj as Record<string, unknown>;
        if (serverName in servers) {
          delete servers[serverName];
          modified = true;
        }
      }
      if (item.cleanClaudeProjects && doc.projects && typeof doc.projects === 'object' && !Array.isArray(doc.projects)) {
        const projects = doc.projects as Record<string, unknown>;
        for (const projVal of Object.values(projects)) {
          if (!projVal || typeof projVal !== 'object' || Array.isArray(projVal)) continue;
          const projObj = projVal as Record<string, unknown>;
          if (projObj.mcpServers && typeof projObj.mcpServers === 'object' && !Array.isArray(projObj.mcpServers)) {
            const projServers = projObj.mcpServers as Record<string, unknown>;
            if (serverName in projServers) {
              delete projServers[serverName];
              modified = true;
            }
          }
        }
      }
      if (modified) {
        writeJsonFileAtomic(abs, doc);
        removedFrom.push(abs);
      }
    } catch {
      // ignore
    }
  }

  return removedFrom;
}

export async function probeMcpEndpoint(
  endpointUrl: string,
  apiKey: string
): Promise<{ ok: boolean; statusCode: number; toolCount?: number; error?: string }> {
  try {
    const initRes = await fetch(endpointUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-03-26',
          capabilities: {},
          clientInfo: { name: 'hebrah-cli-mcp-status', version: '1.0.0' }
        }
      }),
      signal: AbortSignal.timeout(8_000)
    });

    if (!initRes.ok) {
      return {
        ok: false,
        statusCode: initRes.status,
        error: `HTTP ${initRes.status}`
      };
    }

    const sessionId = initRes.headers.get('mcp-session-id');
    const listHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      Authorization: `Bearer ${apiKey}`
    };
    if (sessionId) {
      listHeaders['mcp-session-id'] = sessionId;
    }

    const toolsRes = await fetch(endpointUrl, {
      method: 'POST',
      headers: listHeaders,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
        params: {}
      }),
      signal: AbortSignal.timeout(8_000)
    });

    if (!toolsRes.ok) {
      return { ok: true, statusCode: initRes.status };
    }

    const rawBody = await toolsRes.text();
    let toolCount: number | undefined;
    try {
      const parsed = JSON.parse(rawBody) as { result?: { tools?: unknown[] } };
      if (Array.isArray(parsed?.result?.tools)) {
        toolCount = parsed.result.tools.length;
      }
    } catch {
      // Handle SSE framing (`data: {...}`)
      const dataLine = rawBody
        .split(/\r?\n/)
        .find((line) => line.startsWith('data: '));
      if (dataLine) {
        try {
          const parsed = JSON.parse(dataLine.slice(6)) as { result?: { tools?: unknown[] } };
          if (Array.isArray(parsed?.result?.tools)) {
            toolCount = parsed.result.tools.length;
          }
        } catch {
          // ignore
        }
      }
    }

    return {
      ok: true,
      statusCode: initRes.status,
      toolCount
    };
  } catch (err) {
    return {
      ok: false,
      statusCode: 0,
      error: (err as Error).message
    };
  }
}

function showMcpHelp(): void {
  console.log(`hebrah mcp — Install, inspect, and verify the Hebrah Hosted MCP Server

Usage:
  hebrah mcp install [options]      Configure Hebrah MCP at user scope using your saved CLI credentials
  hebrah mcp status [options]       Inspect MCP configs across agents (tokens redacted) & test connectivity
  hebrah mcp command [options]      Print the safe one-line \`claude mcp add -s user\` shell command
  hebrah mcp remove [options]       Remove Hebrah MCP entries from configured clients

Options:
  --client <target>   Target agent client: auto (default), all, claude, cursor, antigravity, windsurf, vscode
  --scope <scope>     Config scope: user (default, loads in all folders) or project (.mcp.json / .cursor/mcp.json)
  --env-id <id>       Pin a default Isolated Health Environment ID (X-Hebrah-Environment-Id header)
  --mcp-url <url>     Explicit MCP endpoint URL (default: https://mcp.hebrah.com/mcp)
  --name <name>       MCP server key name (default: hebrah)
  --offline           Skip live HTTP probe during \`hebrah mcp status\`
  --json              Output as JSON (tokens always redacted)

Examples:
  hebrah mcp install
  hebrah mcp install --client claude
  hebrah mcp install --client cursor --env-id env-abc123
  hebrah mcp status
`);
}

export default async function mcp(
  _args: string[],
  options: Record<string, unknown> = {}
): Promise<number> {
  const argv = getArgv(options, _args);
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      client: { type: 'string' },
      scope: { type: 'string' },
      'mcp-url': { type: 'string' },
      'env-id': { type: 'string' },
      name: { type: 'string' },
      key: { type: 'string' },
      'home-dir': { type: 'string' },
      cwd: { type: 'string' },
      offline: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: true
  });

  const rawKey = values.key as string | undefined;
  if (rawKey) {
    scrubProcessArgvSecret(rawKey);
  }

  if (values.help) {
    showMcpHelp();
    return 0;
  }

  const subcommand = (positionals[0] ?? (values.client ? 'install' : 'status')).toLowerCase();
  if (subcommand === 'help') {
    showMcpHelp();
    return 0;
  }

  const serverName = sanitizeTerminalText(((values.name as string | undefined) ?? 'hebrah').trim());
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(serverName)) {
    error('Server --name must be 1–64 alphanumeric, hyphen, or underscore characters.');
    return 1;
  }

  const rawScope = ((values.scope as string | undefined) ?? 'user').trim().toLowerCase();
  if (rawScope !== 'user' && rawScope !== 'project' && rawScope !== 'local') {
    error('--scope must be "user" (recommended, loads in all folders) or "project".');
    return 1;
  }
  const scope: McpScope = rawScope === 'project' || rawScope === 'local' ? 'project' : 'user';

  const homeDir = (values['home-dir'] as string | undefined) ?? homedir();
  const cwd = (values.cwd as string | undefined) ?? process.cwd();

  let endpointUrl: string;
  try {
    endpointUrl = resolveMcpEndpoint(values['mcp-url'] as string | undefined);
  } catch (err) {
    error((err as Error).message);
    return 1;
  }

  const creds = loadCredentials();
  const rawEnvId =
    (values['env-id'] as string | undefined) ??
    process.env.HEBRAH_ENV_ID ??
    creds?.defaultEnvId;
  let envId: string | undefined;
  if (rawEnvId) {
    try {
      safeId(rawEnvId.trim(), 'env-id');
      envId = rawEnvId.trim();
    } catch (err) {
      error((err as Error).message);
      return 1;
    }
  }

  if (subcommand === 'command') {
    const jqCommand = `claude mcp add -s user --transport http ${serverName} ${endpointUrl} --header "Authorization: Bearer $(jq -r .apiKey ~/.hebrah/credentials)"`;
    if (values.json) {
      json({
        ok: true,
        serverName,
        endpointUrl,
        claudeCodeCommand: jqCommand,
        cliInstallCommand: 'npx --yes @hebrah/cli@latest mcp install'
      });
      return 0;
    }
    console.log(jqCommand);
    return 0;
  }

  if (subcommand === 'remove' || subcommand === 'uninstall') {
    const removedFrom = removeMcpFromClients({ serverName, homeDir, cwd });
    if (values.json) {
      json({ ok: true, serverName, removedFrom });
      return 0;
    }
    if (removedFrom.length === 0) {
      info(`No "${serverName}" MCP server entries found to remove.`);
    } else {
      for (const filePath of removedFrom) {
        success(`Removed "${serverName}" MCP entry from ${bold(filePath)}`);
      }
    }
    return 0;
  }

  if (subcommand === 'install' || subcommand === 'add' || subcommand === 'setup') {
    const apiKey = (rawKey ?? process.env.HEBRAH_API_KEY ?? creds?.apiKey ?? '').trim();
    if (!apiKey) {
      error('No Hebrah credentials found.');
      info('Run `hebrah login` (or `hebrah signup`) first, then run `hebrah mcp install`.');
      return 2;
    }
    if (!isValidApiKeyFormat(apiKey)) {
      error('API key must start with hb_conn_, hb_pat_, hb_live_, or hb_test_ (minimum 16 characters).');
      return 1;
    }

    let targets: McpClientTarget[];
    try {
      targets = resolveTargets(values.client as string | undefined, scope, homeDir);
    } catch (err) {
      error((err as Error).message);
      return 1;
    }

    const results: McpClientInstallResult[] = [];
    for (const target of targets) {
      const res = installMcpForClient({
        client: target,
        scope,
        endpointUrl,
        apiKey,
        envId,
        serverName,
        homeDir,
        cwd
      });
      results.push(res);
    }

    if (values.json) {
      json({
        ok: true,
        serverName,
        endpointUrl,
        scope,
        keyPrefix: maskApiKey(apiKey),
        envId: envId ?? null,
        installed: results
      });
      return 0;
    }

    console.log();
    for (const res of results) {
      success(
        `Configured ${bold(res.label)} (${res.scope} scope) → ${cyan(res.configPath)} [key: ${res.keyPrefix}]`
      );
      if (res.cleanedLocalOverrides && res.cleanedLocalOverrides.length > 0) {
        info(
          `Cleaned ${res.cleanedLocalOverrides.length} local-scope "${serverName}" override(s) in ~/.claude.json (${res.cleanedLocalOverrides.join(', ')}) so user scope loads in every folder.`
        );
      }
    }
    console.log();
    info('Both agent/CLI keys (hb_conn_*) and dashboard tokens (hb_pat_*) are supported.');
    info('Verify anytime with `hebrah mcp status` (redacts tokens so they never leak into agent transcripts).');
    return 0;
  }

  if (subcommand === 'status' || subcommand === 'check' || subcommand === 'doctor') {
    const entries = inspectConfiguredMcpClients({ serverName, homeDir, cwd });
    const apiKey = (rawKey ?? process.env.HEBRAH_API_KEY ?? creds?.apiKey ?? '').trim();
    const probeResult =
      !values.offline && isValidApiKeyFormat(apiKey)
        ? await probeMcpEndpoint(endpointUrl, apiKey)
        : null;

    if (values.json) {
      json({
        ok: true,
        serverName,
        endpointUrl,
        credentialsSaved: isValidApiKeyFormat(apiKey),
        credentialsKeyPrefix: isValidApiKeyFormat(apiKey) ? maskApiKey(apiKey) : null,
        entries,
        liveProbe: probeResult
      });
      return 0;
    }

    console.log();
    kv([
      ['MCP Server Name', serverName],
      ['MCP Endpoint', endpointUrl],
      [
        'Saved CLI Key',
        isValidApiKeyFormat(apiKey)
          ? `${green(maskApiKey(apiKey))} (~/.hebrah/credentials)`
          : yellow('Not logged in (`hebrah login`)')
      ],
      ...(probeResult
        ? [
            [
              'Live MCP Probe',
              probeResult.ok
                ? green(
                    `Connected (HTTP ${probeResult.statusCode}${typeof probeResult.toolCount === 'number' ? `, ${probeResult.toolCount} tools available` : ''})`
                  )
                : yellow(`Unreachable (${probeResult.error ?? `HTTP ${probeResult.statusCode}`})`)
            ] as [string, string]
          ]
        : [])
    ]);
    console.log();

    if (entries.length === 0) {
      warn('No Hebrah MCP client configurations found yet.');
      info('Run `hebrah mcp install` to configure Claude Code (~/.claude.json user scope) and Cursor (~/.cursor/mcp.json).');
      return 0;
    }

    const rows: string[][] = entries.map((e) => [
      e.label,
      e.scope,
      e.hasBearerToken ? (e.validTokenFormat ? green(e.keyPrefix) : yellow(e.keyPrefix)) : yellow('MISSING TOKEN'),
      e.configPath
    ]);
    table(['CLIENT', 'SCOPE', 'AUTH HEADER (REDACTED)', 'CONFIG FILE'], rows);

    const allWarnings = entries.flatMap((e) =>
      e.warnings.map((w) => `${e.label}: ${ redactSecrets(w) }`)
    );
    if (allWarnings.length > 0) {
      console.log();
      for (const w of allWarnings) {
        warn(w);
      }
    }
    return 0;
  }

  error(`Unknown mcp subcommand "${sanitizeTerminalText(subcommand)}".`);
  info('Run `hebrah mcp --help` for usage (install, status, command, remove).');
  return 1;
}
