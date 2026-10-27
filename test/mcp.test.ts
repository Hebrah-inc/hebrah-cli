import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import mcp from '../src/commands/mcp.js';
import { saveCredentials } from '../src/config/credentials.js';

describe('hebrah mcp command', () => {
  let tempDir: string;
  let fakeHome: string;
  let fakeCwd: string;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.restoreAllMocks();
    tempDir = mkdtempSync(join(tmpdir(), 'hebrah-mcp-test-'));
    fakeHome = join(tempDir, 'home');
    fakeCwd = join(tempDir, 'workspace');
    mkdirSync(fakeHome, { recursive: true });
    mkdirSync(fakeCwd, { recursive: true });

    process.env.HEBRAH_CREDENTIALS_DIR = join(fakeHome, '.hebrah');
    delete process.env.HEBRAH_API_KEY;
    delete process.env.HEBRAH_MCP_URL;
    delete process.env.HEBRAH_ENV_ID;

    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('installs Claude Code at user scope and cleans up stale local-scope overrides in ~/.claude.json', async () => {
    const testToken = 'hb_conn_phil_secret_token_9876543210';
    saveCredentials({
      apiKey: testToken,
      orgId: 'org-phil',
      orgName: 'Phil Org',
      keyPrefix: 'hb_conn_phil_s...',
      createdAt: new Date().toISOString()
    });

    // Simulate the broken state from the incident report:
    // 1. A tokenless local entry in ~/Projects
    // 2. A local entry in ~ (/Users/phil-pro) that didn't load in ~/Projects
    const claudeJsonPath = join(fakeHome, '.claude.json');
    writeFileSync(
      claudeJsonPath,
      JSON.stringify(
        {
          projects: {
            '/Users/phil-pro': {
              mcpServers: {
                hebrah: {
                  type: 'http',
                  url: 'https://mcp.hebrah.com/mcp',
                  headers: { Authorization: `Bearer ${testToken}` }
                }
              }
            },
            '/Users/phil-pro/Projects': {
              mcpServers: {
                hebrah: {
                  type: 'http',
                  url: 'https://mcp.hebrah.com/mcp'
                },
                otherServer: {
                  type: 'http',
                  url: 'https://example.com/mcp'
                }
              }
            }
          }
        },
        null,
        2
      ),
      'utf-8'
    );

    const code = await mcp([], {
      _argv: [
        'install',
        '--client',
        'claude,cursor',
        '--home-dir',
        fakeHome,
        '--cwd',
        fakeCwd,
        '--env-id',
        'env-cardio-01'
      ]
    });

    expect(code).toBe(0);

    // Verify ~/.claude.json now has hebrah at top-level user scope AND local overrides were cleaned
    const updatedClaude = JSON.parse(readFileSync(claudeJsonPath, 'utf-8')) as {
      mcpServers: Record<string, { type: string; url: string; headers: Record<string, string> }>;
      projects: Record<string, { mcpServers: Record<string, unknown> }>;
    };
    expect(updatedClaude.mcpServers.hebrah).toEqual({
      type: 'http',
      url: 'https://mcp.hebrah.com/mcp',
      headers: {
        Authorization: `Bearer ${testToken}`,
        'X-Hebrah-Environment-Id': 'env-cardio-01'
      }
    });
    expect(updatedClaude.projects['/Users/phil-pro'].mcpServers.hebrah).toBeUndefined();
    expect(updatedClaude.projects['/Users/phil-pro/Projects'].mcpServers.hebrah).toBeUndefined();
    // Unrelated MCP servers in projects are preserved
    expect(updatedClaude.projects['/Users/phil-pro/Projects'].mcpServers.otherServer).toBeDefined();

    // Verify ~/.cursor/mcp.json was also written
    const cursorJsonPath = join(fakeHome, '.cursor', 'mcp.json');
    const updatedCursor = JSON.parse(readFileSync(cursorJsonPath, 'utf-8')) as {
      mcpServers: Record<string, { type: string; url: string; headers: Record<string, string> }>;
    };
    expect(updatedCursor.mcpServers.hebrah.url).toBe('https://mcp.hebrah.com/mcp');
    expect(updatedCursor.mcpServers.hebrah.headers.Authorization).toBe(`Bearer ${testToken}`);

    // Ensure full token was NEVER printed to stdout
    const allStdout = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(allStdout).not.toContain(testToken);
    expect(allStdout).toContain('Cleaned 2 local-scope "hebrah" override(s)');
  });

  it('supports Antigravity, Windsurf, and VS Code config formats', async () => {
    const testPat = 'hb_pat_universal_token_abcdef123456';
    saveCredentials({
      apiKey: testPat,
      orgId: 'org-1',
      orgName: 'Org 1',
      keyPrefix: 'hb_pat_univers...',
      createdAt: new Date().toISOString()
    });

    const code = await mcp([], {
      _argv: [
        'install',
        '--client',
        'antigravity,windsurf,vscode',
        '--home-dir',
        fakeHome,
        '--cwd',
        fakeCwd
      ]
    });
    expect(code).toBe(0);

    const antigravityDoc = JSON.parse(
      readFileSync(join(fakeHome, '.gemini', 'antigravity', 'mcp_config.json'), 'utf-8')
    );
    expect(antigravityDoc.mcpServers.hebrah.serverUrl).toBe('https://mcp.hebrah.com/mcp');
    expect(antigravityDoc.mcpServers.hebrah.headers.Authorization).toBe(`Bearer ${testPat}`);

    const windsurfDoc = JSON.parse(
      readFileSync(join(fakeHome, '.codeium', 'windsurf', 'mcp_config.json'), 'utf-8')
    );
    expect(windsurfDoc.mcpServers.hebrah.serverUrl).toBe('https://mcp.hebrah.com/mcp');

    const vscodeDoc = JSON.parse(readFileSync(join(fakeCwd, '.vscode', 'mcp.json'), 'utf-8'));
    expect(vscodeDoc.servers.hebrah.type).toBe('http');
    expect(vscodeDoc.servers.hebrah.url).toBe('https://mcp.hebrah.com/mcp');
  });

  it('redacts tokens in `hebrah mcp status` and warns on local-scope or missing-token entries', async () => {
    const secretToken = 'hb_conn_super_secret_do_not_print_me_12345';
    saveCredentials({
      apiKey: secretToken,
      orgId: 'org-1',
      orgName: 'Org 1',
      keyPrefix: 'hb_conn_super_...',
      createdAt: new Date().toISOString()
    });

    // Write a local-scope entry without a token + a user-scope entry with a token
    writeFileSync(
      join(fakeHome, '.claude.json'),
      JSON.stringify({
        mcpServers: {
          hebrah: {
            type: 'http',
            url: 'https://mcp.hebrah.com/mcp',
            headers: { Authorization: `Bearer ${secretToken}` }
          }
        },
        projects: {
          '/Users/phil-pro/Projects': {
            mcpServers: {
              hebrah: {
                type: 'http',
                url: 'https://mcp.hebrah.com/mcp'
              }
            }
          }
        }
      }),
      'utf-8'
    );

    const code = await mcp([], {
      _argv: ['status', '--offline', '--json', '--home-dir', fakeHome, '--cwd', fakeCwd]
    });
    expect(code).toBe(0);

    const output = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    // Crucial: raw token must NEVER appear in status output
    expect(output).not.toContain(secretToken);

    const parsed = JSON.parse(output);
    expect(parsed.entries).toHaveLength(2);
    const localEntry = parsed.entries.find((e: { scope: string }) => e.scope === 'local');
    expect(localEntry.hasBearerToken).toBe(false);
    expect(localEntry.warnings.join(' ')).toContain('Missing Authorization: Bearer header');
    expect(localEntry.warnings.join(' ')).toContain('local scope');
  });

  it('prints safe one-line claude mcp add command with -s user on `hebrah mcp command`', async () => {
    const code = await mcp([], { _argv: ['command'] });
    expect(code).toBe(0);
    const output = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain(
      'claude mcp add -s user --transport http hebrah https://mcp.hebrah.com/mcp --header "Authorization: Bearer $(jq -r .apiKey ~/.hebrah/credentials)"'
    );
  });

  it('removes hebrah MCP entries across client configs on `hebrah mcp remove`', async () => {
    const testToken = 'hb_conn_remove_test_token_12345678';
    saveCredentials({
      apiKey: testToken,
      orgId: 'org-1',
      orgName: 'Org 1',
      keyPrefix: 'hb_conn_remove...',
      createdAt: new Date().toISOString()
    });

    await mcp([], {
      _argv: ['install', '--client', 'claude,cursor', '--home-dir', fakeHome, '--cwd', fakeCwd]
    });

    const removeCode = await mcp([], {
      _argv: ['remove', '--home-dir', fakeHome, '--cwd', fakeCwd]
    });
    expect(removeCode).toBe(0);

    const claudeDoc = JSON.parse(readFileSync(join(fakeHome, '.claude.json'), 'utf-8'));
    expect(claudeDoc.mcpServers.hebrah).toBeUndefined();
  });
});
