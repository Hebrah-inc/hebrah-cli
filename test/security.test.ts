import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateBrowserUrl } from '../src/util/browser.js';
import {
  isValidApiKeyFormat,
  maskApiKey,
  saveCredentials,
  loadCredentials,
  clearCredentials,
  credentialsPath
} from '../src/config/credentials.js';
import {
  safeId,
  validateApiBaseUrl,
  inferApiUrlFromAppUrl,
  CLI_VERSION,
  api
} from '../src/api/client.js';
import whoami from '../src/commands/whoami.js';
import wallet from '../src/commands/wallet.js';
import login from '../src/commands/login.js';
import env from '../src/commands/env.js';

describe('CLI Security, Anti-Tampering & Onboarding Suite (v0.4.0)', () => {
  let tempDir: string;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.restoreAllMocks();
    tempDir = mkdtempSync(join(tmpdir(), 'hebrah-cli-sec-'));
    process.env.HEBRAH_CREDENTIALS_DIR = tempDir;
    delete process.env.HEBRAH_API_KEY;
    delete process.env.HEBRAH_API_URL;
    api.setBaseUrl(null);
    api.setApiKey(null);
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    delete process.env.HEBRAH_CREDENTIALS_DIR;
    api.setBaseUrl(null);
    api.setApiKey(null);
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  describe('S-1: OS Command Injection Prevention (validateBrowserUrl)', () => {
    it('allows valid https and localhost http URLs', () => {
      expect(validateBrowserUrl('https://app.hebrah.com/cli/authorize?port=54321')).toContain(
        'https://app.hebrah.com/cli/authorize'
      );
      expect(validateBrowserUrl('http://localhost:3020/cli/authorize')).toContain(
        'http://localhost:3020/cli/authorize'
      );
      expect(validateBrowserUrl('http://127.0.0.1:3020/callback')).toContain(
        'http://127.0.0.1:3020/callback'
      );
    });

    it('rejects non-http protocols (file://, javascript:, data:)', () => {
      expect(() => validateBrowserUrl('javascript:alert(1)')).toThrow();
      expect(() => validateBrowserUrl('file:///etc/passwd')).toThrow();
    });

    it('rejects non-HTTPS remote URLs', () => {
      expect(() => validateBrowserUrl('http://evil.example.com/phish')).toThrow(
        /HTTPS/i
      );
    });

    it('rejects shell metacharacters and control characters', () => {
      expect(() => validateBrowserUrl('https://app.hebrah.com/cli` calc.exe`')).toThrow();
      expect(() => validateBrowserUrl('https://app.hebrah.com/cli$(whoami)')).toThrow();
      expect(() => validateBrowserUrl('https://app.hebrah.com/cli\x00')).toThrow();
    });
  });

  describe('S-2 & Gap 2: URL Path Traversal, HTTPS Enforcement & Credential Origin Pinning', () => {
    it('safeId allows valid UUIDs and identifiers', () => {
      expect(safeId('4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94', 'environment_id')).toBe(
        '4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94'
      );
      expect(safeId('conn_12345_abc', 'connection_id')).toBe('conn_12345_abc');
    });

    it('safeId blocks path traversal and query injection payloads', () => {
      expect(() => safeId('../admin/users', 'environment_id')).toThrow(/Invalid environment_id/);
      expect(() => safeId('env-1?admin=true#', 'environment_id')).toThrow(/Invalid environment_id/);
      expect(() => safeId('env-1/../../secret', 'environment_id')).toThrow(/Invalid environment_id/);
    });

    it('validateApiBaseUrl enforces HTTPS and trusted domains unless override is set', () => {
      expect(validateApiBaseUrl('https://api.hebrah.com/')).toBe('https://api.hebrah.com');
      expect(
        validateApiBaseUrl('https://hebrah-staging-api-76zyj6ngda-uc.a.run.app')
      ).toBe('https://hebrah-staging-api-76zyj6ngda-uc.a.run.app');
      expect(validateApiBaseUrl('http://localhost:8000')).toBe('http://localhost:8000');

      // Plain HTTP on remote host is rejected
      expect(() => validateApiBaseUrl('http://api.hebrah.com')).toThrow(
        /refusing cleartext HTTP/
      );

      // Untrusted domain is rejected to prevent Bearer token exfiltration
      expect(() => validateApiBaseUrl('https://attacker-collector.evil.com')).toThrow(
        /untrusted Hebrah host/
      );
    });

    it('inferApiUrlFromAppUrl accurately maps Cloud Run, staging, and local URLs', () => {
      expect(
        inferApiUrlFromAppUrl('https://hebrah-staging-app-76zyj6ngda-uc.a.run.app')
      ).toBe('https://hebrah-staging-api-76zyj6ngda-uc.a.run.app');
      expect(inferApiUrlFromAppUrl('https://app.hebrah.com')).toBe('https://api.hebrah.com');
      expect(inferApiUrlFromAppUrl('http://localhost:3020')).toBe('http://localhost:8000');
    });

    it('Credential Origin Pinning blocks sending saved API key to mismatched origin', async () => {
      saveCredentials({
        apiKey: 'hb_conn_test1234567890abcdef',
        orgId: 'org-1',
        orgName: 'Test Org',
        keyPrefix: 'hb_conn_test12...',
        apiUrl: 'https://hebrah-staging-api-76zyj6ngda-uc.a.run.app',
        createdAt: new Date().toISOString()
      });

      // Attempt to point API to production while saved credentials are pinned to staging
      api.setBaseUrl('https://api.hebrah.com');
      await expect(api.get('/v1/environments')).rejects.toThrow(/pinned to/);
    });
  });

  describe('S-3: Secret Redaction in whoami & maskApiKey', () => {
    it('masks API keys leaving only prefix and hiding secret suffix', () => {
      const masked = maskApiKey('hb_conn_1234567890abcdef9999');
      expect(masked).toBe('hb_conn_123456...');
      expect(masked).not.toContain('7890abcdef9999');
    });

    it('redacts raw apiKey in whoami --json output', async () => {
      saveCredentials({
        apiKey: 'hb_pat_supersecretvalue12345678',
        orgId: 'org-staging-1',
        orgName: 'Staging Org',
        keyPrefix: maskApiKey('hb_pat_supersecretvalue12345678'),
        apiUrl: 'https://hebrah-staging-api-76zyj6ngda-uc.a.run.app',
        defaultEnvId: '4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94',
        createdAt: '2026-10-14T00:00:00Z'
      });

      vi.spyOn(api, 'get').mockResolvedValueOnce({
        orgId: 'org-staging-1',
        orgName: 'Staging Org',
        tier: 'trial',
        period: { start: '2026-10-01', end: '2026-11-01' },
        queries: 5,
        queriesDenied: 0,
        egressBytes: 1024,
        quota: { queries: 1000, egressBytes: 50000000 },
        remaining: { queries: 995, egressBytes: 49998976 },
        balanceCents: 494
      });

      const code = await whoami([], { json: true, _argv: ['--json'] });
      expect(code).toBe(0);

      const output = logSpy.mock.calls.map((c) => c[0]).join('\n');
      expect(output).not.toContain('hb_pat_supersecretvalue12345678');
      expect(output).toContain('hb_pat_superse...');
      expect(output).toContain('4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94');
    });
  });

  describe('S-4: WireGuard PrivateKey Protection & 0600 Permissions', () => {
    it('redacts PrivateKey in stdout/JSON and enforces 0600 on --out file', async () => {
      vi.spyOn(api, 'get').mockResolvedValue({
        environment_id: 'env-wg-sec',
        client_ip: '10.42.0.9/32',
        server_endpoint: 'wg.hebrah.com:51820',
        config_text: '[Interface]\nPrivateKey = SUPER_SECRET_WG_PRIVATE_KEY_XYZ=\nAddress = 10.42.0.9/32\n'
      });

      // 1. Check JSON stdout redaction
      const code1 = await env(['wireguard', 'env-wg-sec', '--json'], {
        json: true,
        _argv: ['wireguard', 'env-wg-sec', '--json']
      });
      expect(code1).toBe(0);
      const jsonOut = logSpy.mock.calls.map((c) => c[0]).join('\n');
      expect(jsonOut).not.toContain('SUPER_SECRET_WG_PRIVATE_KEY_XYZ=');
      expect(jsonOut).toContain('<redacted');

      // 2. Check --out file permissions (0600) and symlink guard
      const outPath = join(tempDir, 'wg-test.conf');
      const code2 = await env(['wireguard', 'env-wg-sec', '--out', outPath], {
        out: outPath,
        _argv: ['wireguard', 'env-wg-sec', '--out', outPath]
      });
      expect(code2).toBe(0);
      const stats = statSync(outPath);
      expect(stats.mode & 0o777).toBe(0o600);
      const savedContent = readFileSync(outPath, 'utf8');
      expect(savedContent).toContain('SUPER_SECRET_WG_PRIVATE_KEY_XYZ=');

      // 3. Reject writing to symlink
      const symlinkTarget = join(tempDir, 'target.txt');
      const symlinkPath = join(tempDir, 'symlink.conf');
      writeFileSync(symlinkTarget, 'original');
      symlinkSync(symlinkTarget, symlinkPath);

      const code3 = await env(['wireguard', 'env-wg-sec', '--out', symlinkPath], {
        out: symlinkPath,
        _argv: ['wireguard', 'env-wg-sec', '--out', symlinkPath]
      });
      expect(code3).toBe(1);
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('symlink'));
    });
  });

  describe('S-5 & Gap 3: Multi-Prefix Validation & Atomic Symlink-Safe Credentials', () => {
    it('accepts hb_conn_, hb_pat_, hb_live_, and hb_test_ prefixes', () => {
      expect(isValidApiKeyFormat('hb_conn_1234567890abcdef')).toBe(true);
      expect(isValidApiKeyFormat('hb_pat_1234567890abcdef')).toBe(true);
      expect(isValidApiKeyFormat('hb_live_1234567890abcdef')).toBe(true);
      expect(isValidApiKeyFormat('hb_test_1234567890abcdef')).toBe(true);
      expect(isValidApiKeyFormat('invalid_key_1234567890')).toBe(false);
      expect(isValidApiKeyFormat('hb_pat_x')).toBe(false);
    });

    it('writes credentials atomically with 0600 permissions and blocks symlinks', () => {
      saveCredentials({
        apiKey: 'hb_pat_atomic1234567890abcdef',
        orgId: 'org-123',
        orgName: 'Atomic Org',
        keyPrefix: 'hb_pat_atomic1...',
        apiUrl: 'https://hebrah-staging-api-76zyj6ngda-uc.a.run.app',
        defaultEnvId: '4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94',
        createdAt: '2026-10-14T00:00:00Z'
      });

      const credFile = credentialsPath();
      const st = statSync(credFile);
      expect(st.mode & 0o777).toBe(0o600);

      const loaded = loadCredentials();
      expect(loaded?.apiKey).toBe('hb_pat_atomic1234567890abcdef');
      expect(loaded?.defaultEnvId).toBe('4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94');

      // Replace credentials file with a symlink and verify load/save refuse it
      clearCredentials();
      const targetFile = join(tempDir, 'victim.json');
      writeFileSync(targetFile, '{}');
      symlinkSync(targetFile, credFile);

      expect(() => loadCredentials()).toThrow(/symbolic link/);
      expect(() =>
        saveCredentials({
          apiKey: 'hb_conn_1234567890abcdef',
          orgId: 'org-123',
          orgName: 'Atomic Org',
          keyPrefix: 'hb_conn_123456...',
          createdAt: '2026-10-14T00:00:00Z'
        })
      ).toThrow(/symbolic link/);
    });
  });

  describe('S-6: Wallet Cents Formatting Fix', () => {
    it('divides balance_cents, threshold_cents, amount_cents, and cost_cents by 100 accurately', async () => {
      saveCredentials({
        apiKey: 'hb_conn_wallet1234567890abcdef',
        orgId: 'org-wallet',
        orgName: 'Wallet Org',
        keyPrefix: 'hb_conn_wallet...',
        createdAt: '2026-10-14T00:00:00Z'
      });

      vi.spyOn(api, 'get').mockResolvedValueOnce({
        org_id: 'org-wallet',
        tier: 'pro',
        balance_cents: 500,
        auto_reload: {
          enabled: true,
          threshold_cents: 200,
          amount_cents: 2000,
          stripe_customer_linked: true
        },
        burn_30d: {
          window_days: 30,
          queries: 10,
          cost_cents: 50,
          avg_cost_per_query_cents: 0.005
        },
        projected_days_to_empty: 30
      });

      const code = await wallet([], { _argv: [] });
      expect(code).toBe(0);
      const output = logSpy.mock.calls.map((c) => c[0]).join('\n');
      expect(output).toContain('$5.00');
      expect(output).toContain('$2.00');
      expect(output).toContain('$20.00');
      expect(output).toContain('$0.50');
    });
  });

  describe('Workstreams 2 & 3: Staging Login & Environment Connection Handshake', () => {
    it('hebrah login --key with --app-url and --env-id infers staging API, persists config, and binds environment', async () => {
      const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce({
        orgId: 'org-staging-memorial',
        orgName: 'Memorial Hospital Org',
        tier: 'trial'
      });
      const postSpy = vi.spyOn(api, 'post').mockResolvedValueOnce({
        id: '4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94',
        name: 'Memorial Hospital integration',
        clinic_type: 'hospital_system',
        status: 'active',
        addons: ['postgres'],
        endpoints: {
          fhir: 'https://hebrah-staging-api-76zyj6ngda-uc.a.run.app/v1/environments/4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94/fhir'
        }
      });

      const argv = [
        '--key',
        'hb_pat_stagingkey1234567890abcdef',
        '--app-url',
        'https://hebrah-staging-app-76zyj6ngda-uc.a.run.app',
        '--env-id',
        '4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94',
        '--agent-name',
        'Test Agent'
      ];

      const code = await login(argv, { _argv: argv });

      expect(code).toBe(0);
      expect(getSpy).toHaveBeenCalledWith('/v1/agent/account/usage');
      expect(postSpy).toHaveBeenCalledWith(
        '/v1/environments/4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94/agents/connect',
        { agent_name: 'Test Agent', client: 'hebrah-cli' }
      );

      const saved = loadCredentials();
      expect(saved?.apiUrl).toBe('https://hebrah-staging-api-76zyj6ngda-uc.a.run.app');
      expect(saved?.appUrl).toBe('https://hebrah-staging-app-76zyj6ngda-uc.a.run.app');
      expect(saved?.defaultEnvId).toBe('4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94');
    });

    it('hebrah env connect binds to environment and sets defaultEnvId for subsequent env commands', async () => {
      saveCredentials({
        apiKey: 'hb_conn_test1234567890abcdef',
        orgId: 'org-1',
        orgName: 'Memorial Hospital Org',
        keyPrefix: 'hb_conn_test12...',
        apiUrl: 'https://hebrah-staging-api-76zyj6ngda-uc.a.run.app',
        createdAt: '2026-10-14T00:00:00Z'
      });

      const postSpy = vi.spyOn(api, 'post').mockResolvedValueOnce({
        id: '4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94',
        org_id: 'org-1',
        name: 'Memorial Hospital integration',
        clinic_type: 'hospital_system',
        patient_cohort: 'mixed',
        status: 'active',
        addons: ['postgres'],
        patient_count: 50,
        bed_count: 100,
        endpoints: {
          fhir: 'https://hebrah-staging-api-76zyj6ngda-uc.a.run.app/v1/environments/4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94/fhir'
        },
        queries_run: 5,
        bytes_egressed: 1024,
        hourly_rate_cents: 8,
        total_cost_cents: 24,
        connected_agents_count: 1,
        created_at: '2026-10-14T00:00:00Z'
      });

      const code = await env(
        ['connect', '4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94', '--agent-name', 'Cursor Agent'],
        {
          'agent-name': 'Cursor Agent',
          _argv: ['connect', '4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94', '--agent-name', 'Cursor Agent']
        }
      );

      expect(code).toBe(0);
      expect(postSpy).toHaveBeenCalledWith(
        '/v1/environments/4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94/agents/connect',
        expect.objectContaining({
          agent_name: 'Cursor Agent',
          cli_version: CLI_VERSION
        })
      );
      expect(loadCredentials()?.defaultEnvId).toBe('4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94');

      // Subsequent `hebrah env status` without explicit ID uses defaultEnvId!
      const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce({
        id: '4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94',
        name: 'Memorial Hospital integration',
        clinic_type: 'hospital_system',
        patient_cohort: 'mixed',
        status: 'active',
        addons: ['postgres'],
        patient_count: 50,
        bed_count: 100,
        endpoints: {},
        queries_run: 5,
        bytes_egressed: 1024,
        hourly_rate_cents: 8,
        total_cost_cents: 24
      });

      const statusCode = await env(['status'], { _argv: ['status'] });
      expect(statusCode).toBe(0);
      expect(getSpy).toHaveBeenCalledWith(
        '/v1/environments/4e39cc5c-f2f5-435c-a844-cf6b5d3bcb94'
      );
    });
  });

  describe('S-7: Terminal Escape Injection (OSC 52/OSC 8) & Error Secret Redaction', () => {
    it('strips OSC 52 clipboard hijack, OSC 8 links, and control chars while redacting tokens', async () => {
      const { sanitizeTerminalText, redactSecrets } = await import('../src/output/format.js');
      const malicious =
        'Patient Name \x1b]52;c;ZWNobyBoYWNrZWQ=\x07 \x1b]8;;https://evil.com\x07Click\x1b]8;;\x07 \x1b[2J';
      const cleaned = sanitizeTerminalText(malicious);
      expect(cleaned).not.toContain('\x1b]52');
      expect(cleaned).not.toContain('\x1b]8');
      expect(cleaned).not.toContain('\x1b[2J');
      expect(cleaned).toContain('Patient Name');

      const leaked =
        'Error: key=hb_live_1234567890abcdef and vault=enc:v1:999999999999 and PrivateKey = SECRET_WG_KEY';
      const redacted = redactSecrets(leaked);
      expect(redacted).not.toContain('hb_live_1234567890abcdef');
      expect(redacted).not.toContain('enc:v1:999999999999');
      expect(redacted).not.toContain('SECRET_WG_KEY');
      expect(redacted).toContain('[REDACTED_HEBRAH_TOKEN]');
    });

    it('CLI-F2: strips 8-bit C1 escape sequences (\\x9b, \\x9d, \\x90) and sanitizes kv/info/warn/error while preserving SGR colors', async () => {
      const { sanitizeTerminalText, kv } = await import('../src/output/format.js');
      const c1Payload = 'Clinical Note \x9d52;c;ZWNobyBoYWNrZWQ=\x07 \x9b2J \x90Pwned\x9c Safe';
      const cleaned = sanitizeTerminalText(c1Payload);
      expect(cleaned).not.toContain('\x9d');
      expect(cleaned).not.toContain('\x9b');
      expect(cleaned).not.toContain('\x90');
      expect(cleaned).toContain('Clinical Note');
      expect(cleaned).toContain('Safe');

      const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      kv([['Endpoint', '\x1b[32mhttps://api.hebrah.com\x1b[0m\x1b]52;c;evil\x07\x1b[2J']]);
      const logged = String(logSpy.mock.calls.at(-1)?.[0] ?? '');
      expect(logged).not.toContain(']52;');
      expect(logged).not.toContain('\x1b[2J');
      expect(logged).toContain('https://api.hebrah.com');
    });
  });

  describe('S-8: CLI Pen-Test Hardening (CLI-F1 through CLI-F6)', () => {
    it('CLI-F1: rejects percent-encoded path traversal (%2e%2e, %2f, %5c, %00) in HebrahApi.request and inspect command', async () => {
      await expect(api.get('/v1/connections/targets/%2e%2e/admin')).rejects.toThrow(/invalid API request path/i);
      await expect(api.get('/v1/environments/env_1%2f..%2fsecret')).rejects.toThrow(/invalid API request path/i);
      await expect(api.get('/v1/environments/env_1%5c..')).rejects.toThrow(/invalid API request path/i);
      await expect(api.get('/v1/environments/env_1%00.json')).rejects.toThrow(/invalid API request path/i);

      const { default: inspect } = await import('../src/commands/inspect.js');
      const code = await inspect(['../admin'], { _argv: ['../admin'] });
      expect(code).toBe(4);
    });

    it('CLI-F3: refuses to bind local PostgreSQL wire proxy to non-loopback interfaces (0.0.0.0 or LAN IP)', async () => {
      const { startPgWireProxy } = await import('../src/util/pgProxy.js');
      await expect(
        startPgWireProxy({
          envId: 'env_123',
          host: '0.0.0.0',
          port: 15432,
          database: 'hebrah',
          client: api
        })
      ).rejects.toThrow(/loopback/i);

      await expect(
        startPgWireProxy({
          envId: 'env_123',
          host: '192.168.1.50',
          port: 15432,
          database: 'hebrah',
          client: api
        })
      ).rejects.toThrow(/loopback/i);
    });

    it('CLI-F4: deeply scrubs and redacts secrets in ApiError.body, ApiError.suggestion, and JSON.stringify(err)', async () => {
      const { ApiError } = await import('../src/api/client.js');
      const err = new ApiError(
        'Upstream failure with token hb_live_abcdef1234567890\x1b]52;c;evil\x07',
        500,
        {
          detail: 'Vault failure for enc:v1:deadbeefcafebabe1234',
          nested: {
            auth: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            wg: 'PrivateKey = SECRET_WIREGUARD_PRIVATE_KEY_VALUE'
          }
        },
        'Retry with key hb_pat_9876543210fedcba'
      );

      const serialized = JSON.stringify(err);
      expect(serialized).not.toContain('hb_live_abcdef1234567890');
      expect(serialized).not.toContain('deadbeefcafebabe1234');
      expect(serialized).not.toContain('SECRET_WIREGUARD_PRIVATE_KEY_VALUE');
      expect(serialized).not.toContain('hb_pat_9876543210fedcba');
      expect(serialized).not.toContain(']52;');
      expect(serialized).toContain('[REDACTED_HEBRAH_TOKEN]');
      expect(serialized).toContain('enc:v1:[REDACTED]');
    });

    it('CLI-F5: does not silently downgrade to cleartext http://localhost:8000 when using production origin', async () => {
      const { ensureEnvironmentOrigin } = await import('../src/commands/db.js');
      const prevVitest = process.env.VITEST;
      const prevAllow = process.env.HEBRAH_ALLOW_LOCAL_FALLBACK;
      try {
        delete process.env.VITEST;
        delete process.env.HEBRAH_ALLOW_LOCAL_FALLBACK;
        saveCredentials({
          apiKey: 'hb_live_prod_secret_token',
          apiUrl: 'https://api.hebrah.com'
        });
        api.setBaseUrl('https://api.hebrah.com');

        const getSpy = vi.spyOn(api, 'get').mockRejectedValue(new Error('Network error'));
        await ensureEnvironmentOrigin('env_123', {});

        // Should not have probed or switched to http://localhost:8000
        expect(api.getBaseUrl()).toBe('https://api.hebrah.com');
        expect(getSpy).not.toHaveBeenCalled();
      } finally {
        process.env.VITEST = prevVitest;
        if (prevAllow === undefined) {
          delete process.env.HEBRAH_ALLOW_LOCAL_FALLBACK;
        } else {
          process.env.HEBRAH_ALLOW_LOCAL_FALLBACK = prevAllow;
        }
      }
    });
  });

  describe('S-9: Second-Pass Production Readiness & Pen-Test Hardening', () => {
    it('CLI-S9-1: validateCheckoutUrl enforces HTTPS and trusted Stripe/Hebrah hosts', async () => {
      const { validateCheckoutUrl } = await import('../src/commands/topup.js');

      expect(validateCheckoutUrl('https://checkout.stripe.com/c/pay/cs_test_123')).toBe(
        'https://checkout.stripe.com/c/pay/cs_test_123'
      );
      expect(validateCheckoutUrl('https://billing.stripe.com/p/session/123')).toBe(
        'https://billing.stripe.com/p/session/123'
      );
      expect(validateCheckoutUrl('https://app.hebrah.com/settings/billing')).toBe(
        'https://app.hebrah.com/settings/billing'
      );

      expect(() => validateCheckoutUrl('https://evil-phishing.example.com/pay')).toThrow(
        /untrusted Hebrah host/i
      );
      expect(() => validateCheckoutUrl('http://checkout.stripe.com/c/pay/cs_test_123')).toThrow(
        /HTTPS/i
      );
      expect(() => validateCheckoutUrl('https://user:pass@checkout.stripe.com/pay')).toThrow(
        /embedded credentials/i
      );
    });

    it('CLI-S9-2: resolveAppUrl validates --app-url and HEBRAH_APP_URL against SSRF and cleartext', async () => {
      const { resolveAppUrl } = await import('../src/commands/login.js');

      expect(resolveAppUrl('https://app.hebrah.com/')).toBe('https://app.hebrah.com');
      expect(resolveAppUrl('http://localhost:3020/')).toBe('http://localhost:3020');

      expect(() => resolveAppUrl('http://evil.example.com')).toThrow(/cleartext HTTP/i);
      expect(() => resolveAppUrl('https://169.254.169.254')).toThrow(/cloud metadata or link-local host|untrusted Hebrah host/i);
      expect(() => resolveAppUrl('https://admin:secret@app.hebrah.com')).toThrow(
        /embedded credentials/i
      );
    });

    it('CLI-S9-3: validateApiBaseUrl and validateBrowserUrl block embedded credentials and 8-bit C1 controls', () => {
      expect(() => validateApiBaseUrl('https://user:pass@api.hebrah.com')).toThrow(
        /embedded credentials/i
      );
      expect(() => validateApiBaseUrl('https://api.hebrah.com/\x9b2J')).toThrow(
        /control characters/i
      );
      expect(() => validateBrowserUrl('https://user:pass@app.hebrah.com/login')).toThrow(
        /embedded credentials/i
      );
      expect(() => validateBrowserUrl('https://app.hebrah.com/\x9d52;c;YWJj')).toThrow(
        /unsafe or disallowed characters/i
      );
    });

    it('CLI-S9-4: redactSecrets scrubs DB connection URI passwords while preserving user and host', async () => {
      const { redactSecrets } = await import('../src/output/format.js');

      const raw = 'Target: postgresql://ehr_admin:Sup3rS3cretP@ss!@db.internal.hospital.org:5432/clinical_prod';
      const scrubbed = redactSecrets(raw);
      expect(scrubbed).not.toContain('Sup3rS3cretP');
      expect(scrubbed).toContain('postgresql://ehr_admin:[REDACTED]@db.internal.hospital.org:5432/clinical_prod');
    });

    it('CLI-S9-5: json() escapes 8-bit C1 control characters and colorize() sanitizes even when NO_COLOR=1', async () => {
      const { json, bold } = await import('../src/output/format.js');

      json({
        evilC1: 'prefix\x9b2J\x9d52;c;YWJj\x9csuffix',
        dbUri: 'redis://default:my_redis_secret_pw@cache.internal:6379/0'
      });

      const emitted = String(logSpy.mock.calls[0]?.[0] ?? '');
      expect(emitted).not.toContain('\x9b');
      expect(emitted).not.toContain('\x9d');
      expect(emitted).toContain('\\u009b');
      expect(emitted).toContain('\\u009d');
      expect(emitted).not.toContain('my_redis_secret_pw');
      expect(emitted).toContain('redis://default:[REDACTED]@cache.internal:6379/0');

      const prevNoColor = process.env.NO_COLOR;
      try {
        process.env.NO_COLOR = '1';
        const rendered = bold('Safe\x1b]52;c;YWJj\x07Title\x9b2J');
        expect(rendered).toBe('SafeTitle');
        expect(rendered).not.toContain('\x1b');
        expect(rendered).not.toContain('\x9b');
      } finally {
        if (prevNoColor === undefined) {
          delete process.env.NO_COLOR;
        } else {
          process.env.NO_COLOR = prevNoColor;
        }
      }
    });

    it('CLI-S9-6: signup --json masks raw apiKey in stdout while persisting full key to 0600 credentials', async () => {
      const signup = (await import('../src/commands/signup.js')).default;

      vi.spyOn(api, 'post').mockResolvedValueOnce({
        orgId: 'org_sec_99',
        orgName: 'SecTest Agent',
        apiKey: 'hb_live_super_secret_newly_minted_key_123456',
        trial: {
          credits: { queries: 1000, egressBytes: 52428800 },
          expiresAt: '2026-11-01T00:00:00Z'
        },
        claimUrl: 'https://app.hebrah.com/claim-org/hb_claim_secret_token_999'
      });

      const code = await signup(['--headless', '--name', 'SecTest Agent', '--json']);
      expect(code).toBe(0);

      const jsonOut = String(logSpy.mock.calls[0]?.[0] ?? '');
      expect(jsonOut).not.toContain('hb_live_super_secret_newly_minted_key_123456');
      const parsed = JSON.parse(jsonOut);
      expect(parsed.keyPrefix).toContain('hb_live_');

      // Verify full key was saved to credentials file
      const saved = loadCredentials();
      expect(saved?.apiKey).toBe('hb_live_super_secret_newly_minted_key_123456');
    });

    it('CLI-S9-7: query --file rejects files larger than 1 MB', async () => {
      const queryCmd = (await import('../src/commands/query.js')).default;
      const bigFile = join(tempDir, 'huge.sql');
      writeFileSync(bigFile, 'SELECT ' + '1,'.repeat(600_000) + '1;');

      const code = await queryCmd(['conn_123', '--file', bigFile]);
      expect(code).toBe(1);
      const errOut = errorSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(errOut).toContain('SQL file exceeds maximum size of 1 MB');
    });

    it('CLI-S9-8: wallet status renders unlinked card warning cleanly without undefined', async () => {
      saveCredentials({ apiKey: 'hb_live_test_wallet_key_123456' });
      vi.spyOn(api, 'get').mockResolvedValueOnce({
        org_id: 'org_1',
        tier: 'trial',
        balance_cents: 500,
        auto_reload: {
          enabled: true,
          threshold_cents: 200,
          amount_cents: 1000,
          stripe_customer_linked: false
        },
        burn_30d: {
          window_days: 30,
          queries: 10,
          cost_cents: 25,
          avg_cost_per_query_cents: 2.5
        },
        projected_days_to_empty: 12
      });

      const code = await wallet([]);
      expect(code).toBe(0);
      const allLogs = logSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(allLogs).toContain('not linked');
      expect(allLogs).not.toContain('undefined');
    });
  });

  describe('S-10: Third-Pass Pen-Test Hardening (Loopback DNS Rebinding, PG Wire Mutex, Cloud Metadata SSRF, Credentials & Skill Bounds)', () => {
    it('blocks DNS rebinding (Host header mismatch) and cross-origin subresource probes (Sec-Fetch-Mode) on loopback listener without killing the session', async () => {
      const { startLoopbackAuth } = await import('../src/util/loopback.js');
      const net = await import('node:net');
      const listener = await startLoopbackAuth();
      const waitPromise = listener.waitForCallback(10_000);
      const callbackUrl = `http://127.0.0.1:${listener.port}/callback`;

      try {
        // 1. Send a raw HTTP request with a spoofed DNS-rebound Host header (evil.com)
        const sendRawHttp = (rawRequest: string): Promise<string> =>
          new Promise((resolve, reject) => {
            const client = net.createConnection({ host: '127.0.0.1', port: listener.port }, () => {
              client.write(rawRequest);
            });
            let data = '';
            client.on('data', (chunk) => {
              data += chunk.toString('utf8');
            });
            client.on('end', () => resolve(data));
            client.on('error', reject);
          });

        const dnsRebindResp = await sendRawHttp(
          `GET /callback?apiKey=hb_pat_validkey12345678&state=${listener.state} HTTP/1.1\r\nHost: evil.rebind.attacker.com:${listener.port}\r\nConnection: close\r\n\r\n`,
        );
        expect(dnsRebindResp).toContain('403 Forbidden');
        expect(dnsRebindResp).toMatch(/invalid Host header/i);

        // 2. Send a cross-origin subresource probe (Sec-Fetch-Mode: no-cors, Sec-Fetch-Dest: image)
        const subresourceResp = await sendRawHttp(
          `GET /callback?error=access_denied HTTP/1.1\r\nHost: 127.0.0.1:${listener.port}\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Dest: image\r\nConnection: close\r\n\r\n`,
        );
        expect(subresourceResp).toContain('403 Forbidden');
        expect(subresourceResp).toMatch(/cross-origin subresource requests are not permitted/i);

        // 3. Send an unauthenticated error callback with a forged state -> must NOT kill the listener!
        const forgedErrorResp = await fetch(
          `${callbackUrl}?error=access_denied&state=wrong-state-probe`,
        );
        expect(forgedErrorResp.status).toBe(400);

        // 4. Verify the legitimate browser navigation callback still succeeds and sanitizes orgName + validates envId
        const validResp = await fetch(
          `${callbackUrl}?apiKey=hb_pat_validkey12345678&state=${listener.state}&orgId=org_123&orgName=${encodeURIComponent('Acme\x1b[31mHealth')}&envId=${encodeURIComponent('../bad')}`,
        );
        expect(validResp.status).toBe(200);

        const result = await waitPromise;
        expect(result.apiKey).toBe('hb_pat_validkey12345678');
        expect(result.orgId).toBe('org_123');
        expect(result.orgName).toBe('AcmeHealth');
        expect(result.envId).toBeUndefined(); // Unsafe env_id rejected
      } finally {
        listener.close();
      }
    });

    it('serializes concurrent PG wire proxy packets (async mutex), strips embedded null bytes, and redacts secrets in ErrorResponse', async () => {
      const { startPgWireProxy } = await import('../src/util/pgProxy.js');
      const net = await import('node:net');

      let activeExecutions = 0;
      let maxConcurrentExecutions = 0;

      const mockClient = {
        post: async (_path: string, body: unknown) => {
          const sql = String((body as { sql?: string })?.sql ?? '');
          activeExecutions++;
          maxConcurrentExecutions = Math.max(maxConcurrentExecutions, activeExecutions);
          await new Promise((r) => setTimeout(r, 40));
          activeExecutions--;
          if (sql.includes('FAIL_WITH_SECRET')) {
            throw new Error('Upstream failed with token hb_live_secretleak1234567890');
          }
          return {
            columns: ['col\0injected'],
            rows: [{ 'col\0injected': 'val\0injected' }],
            rowCount: 1,
          };
        },
      };

      const handle = await startPgWireProxy({
        envId: 'env_s10_test',
        port: 0,
        requirePassword: false,
        client: mockClient as never,
      });

      try {
        const client = net.createConnection({ host: handle.host, port: handle.port });
        await new Promise<void>((resolve, reject) => {
          client.once('connect', () => resolve());
          client.once('error', reject);
        });

        // Wait for initial ReadyForQuery ('Z\0\0\0\x05I') after StartupMessage
        const readyPromise = new Promise<void>((resolve) => {
          let startupBuf = Buffer.alloc(0);
          const onData = (chunk: Buffer) => {
            startupBuf = Buffer.concat([startupBuf, chunk]);
            for (let i = 0; i <= startupBuf.length - 6; i++) {
              if (
                startupBuf[i] === 0x5a &&
                startupBuf.readInt32BE(i + 1) === 5 &&
                startupBuf[i + 5] === 0x49
              ) {
                client.off('data', onData);
                resolve();
                return;
              }
            }
          };
          client.on('data', onData);
        });

        // StartupMessage (v3.0 = 196608)
        const userBuf = Buffer.from('user\0hebrah\0database\0hebrah\0\0', 'utf8');
        const startup = Buffer.alloc(8 + userBuf.length);
        startup.writeInt32BE(8 + userBuf.length, 0);
        startup.writeInt32BE(196608, 4);
        userBuf.copy(startup, 8);
        client.write(startup);

        await readyPromise;

        // Build two Simple Query ('Q') messages that hit mockClient.post and send them across two TCP writes
        const makeQueryMsg = (sql: string) => {
          const qBuf = Buffer.from(`${sql}\0`, 'utf8');
          const msg = Buffer.alloc(5 + qBuf.length);
          msg[0] = 0x51; // 'Q'
          msg.writeInt32BE(4 + qBuf.length, 1);
          qBuf.copy(msg, 5);
          return msg;
        };

        const donePromise = new Promise<Buffer>((resolve) => {
          let fullBuf = Buffer.alloc(0);
          client.on('data', (chunk: Buffer) => {
            fullBuf = Buffer.concat([fullBuf, chunk]);
            let readyCount = 0;
            for (let i = 0; i <= fullBuf.length - 6; i++) {
              if (
                fullBuf[i] === 0x5a &&
                fullBuf.readInt32BE(i + 1) === 5 &&
                fullBuf[i + 5] === 0x49
              ) {
                readyCount++;
              }
            }
            if (readyCount >= 2) {
              resolve(fullBuf);
            }
          });
        });

        client.write(makeQueryMsg('SELECT id FROM patients'));
        setTimeout(() => {
          client.write(makeQueryMsg('SELECT FAIL_WITH_SECRET FROM patients'));
        }, 5);

        const rawResponse = await donePromise;
        const responseText = rawResponse.toString('utf8');

        // Verify queries were serialized by drainBuffer (never ran concurrently)
        expect(maxConcurrentExecutions).toBe(1);
        // Verify null-byte stripping in column name
        expect(responseText).toContain('colinjected');
        // Verify secret redaction in ErrorResponse
        expect(responseText).not.toContain('hb_live_secretleak1234567890');
        expect(responseText).toContain('[REDACTED_HEBRAH_TOKEN]');

        client.destroy();
      } finally {
        await handle.close();
      }
    });

    it('blocks cloud metadata SSRF endpoints even when HEBRAH_ALLOW_CUSTOM_HOST=1 is set', () => {
      const prevCustomHost = process.env.HEBRAH_ALLOW_CUSTOM_HOST;
      try {
        process.env.HEBRAH_ALLOW_CUSTOM_HOST = '1';

        expect(() => validateApiBaseUrl('https://169.254.169.254/latest/meta-data')).toThrow(
          /cloud metadata or link-local host/i,
        );
        expect(() => validateApiBaseUrl('https://metadata.google.internal/computeMetadata/v1')).toThrow(
          /cloud metadata or link-local host/i,
        );
        expect(() => validateApiBaseUrl('https://100.100.100.200/latest/meta-data')).toThrow(
          /cloud metadata or link-local host/i,
        );
        expect(() => validateApiBaseUrl('https://[fd00:ec2::254]/latest/meta-data')).toThrow(
          /cloud metadata or link-local host/i,
        );
        expect(() => validateBrowserUrl('https://169.254.169.254/latest/meta-data')).toThrow(
          /cloud metadata or link-local host/i,
        );
      } finally {
        if (prevCustomHost === undefined) {
          delete process.env.HEBRAH_ALLOW_CUSTOM_HOST;
        } else {
          process.env.HEBRAH_ALLOW_CUSTOM_HOST = prevCustomHost;
        }
      }
    });

    it('enforces 50 MB API response size cap in HebrahApi', async () => {
      const fetchMock = vi.fn().mockResolvedValue(
        new Response('{}', {
          status: 200,
          headers: { 'content-length': String(60 * 1024 * 1024) },
        }),
      );
      vi.stubGlobal('fetch', fetchMock);

      api.setBaseUrl('https://api.hebrah.com');
      api.setApiKey('hb_pat_validkey12345678');
      await expect(api.get('/v1/agent/whoami')).rejects.toThrow(/exceeds maximum allowed size/i);
    });

    it('enforces strict API key character whitelist and 64 KB size cap in loadCredentials', () => {
      expect(isValidApiKeyFormat('hb_pat_validKey_123-abc.456')).toBe(true);
      expect(isValidApiKeyFormat('hb_live_short')).toBe(false);
      expect(isValidApiKeyFormat('hb_pat_invalid/slash/key12345')).toBe(false);
      expect(isValidApiKeyFormat('hb_pat_invalid?query=1&x=2345')).toBe(false);

      // Write an oversized credentials.json (> 64 KB) and verify loadCredentials rejects it
      const credPath = credentialsPath();
      writeFileSync(
        credPath,
        JSON.stringify({ apiKey: 'hb_pat_validKey12345678', padding: 'A'.repeat(70_000) }),
        { mode: 0o600 },
      );
      expect(() => loadCredentials()).toThrow(/exceeds maximum allowed size/i);
    });

    it('enforces 2 MB size cap and secret redaction in hebrah skill command', async () => {
      const skillCmd = (await import('../src/commands/skill.js')).default;
      const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

      const fetchMock = vi.fn().mockResolvedValue(
        new Response('oversized', {
          status: 200,
          headers: { 'content-length': String(5 * 1024 * 1024) },
        }),
      );
      vi.stubGlobal('fetch', fetchMock);

      try {
        // Falls back to bundled skill.md (code 0) after logging the 2 MB size cap error via error()
        const code = await skillCmd(['--refresh'], { refresh: true });
        expect(code).toBe(0);
        const errOut = errorSpy.mock.calls.map((c) => c.join(' ')).join('\n');
        expect(errOut).toContain('SKILL.md response exceeds maximum size');
      } finally {
        writeSpy.mockRestore();
      }
    });

    it('rejects path-traversal --env-id in signup and login commands before making network calls', async () => {
      const signupCmd = (await import('../src/commands/signup.js')).default;
      const loginCmd = (await import('../src/commands/login.js')).default;

      const signupCode = await signupCmd(['--name', 'Agent', '--env-id', '../etc/passwd']);
      expect(signupCode).toBe(1);

      const loginCode = await loginCmd(['--env-id', 'env_123/../../admin']);
      expect(loginCode).toBe(1);

      const errOut = errorSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(errOut).toMatch(/Invalid env-id/i);
    });
  });

  // =========================================================================
  // S-11: Ephemeral PG Proxy Auth & Stdin/Hidden Login Hardening
  // =========================================================================
  describe('S-11: Ephemeral PG Proxy Auth & Stdin/Hidden Login Hardening', () => {
    it('requires AuthenticationCleartextPassword on 127.0.0.1 PG proxy and rejects wrong passwords or unauthenticated queries with FATAL 28P01', async () => {
      const { startPgWireProxy } = await import('../src/util/pgProxy.js');
      const net = await import('node:net');

      const mockClient = {
        post: vi.fn().mockResolvedValue({
          columns: ['id'],
          rows: [{ id: 'pat-1' }],
          rowCount: 1,
        }),
      };

      const proxy = await startPgWireProxy({
        envId: 'env_s11_auth',
        port: 0,
        client: mockClient as never,
      });

      expect(proxy.password).toMatch(/^[0-9a-f]{32}$/);

      try {
        // Case A: Client sends Simple Query ('Q') immediately after StartupMessage without 'p' PasswordMessage
        const unauthResponse = await new Promise<string>((resolve, reject) => {
          const sock = net.createConnection({ host: proxy.host, port: proxy.port }, () => {
            const startup = Buffer.alloc(8);
            startup.writeInt32BE(8, 0);
            startup.writeInt32BE(196608, 4);
            sock.write(startup);
          });

          let sentQuery = false;
          let buf = Buffer.alloc(0);
          sock.on('data', (chunk: Buffer) => {
            buf = Buffer.concat([buf, chunk]);
            if (!sentQuery && buf[0] === 0x52) {
              sentQuery = true;
              const sqlBytes = Buffer.from('SELECT 1\0', 'utf8');
              const qMsg = Buffer.alloc(5 + sqlBytes.length);
              qMsg[0] = 0x51; // 'Q'
              qMsg.writeInt32BE(4 + sqlBytes.length, 1);
              sqlBytes.copy(qMsg, 5);
              sock.write(qMsg);
            }
          });
          sock.on('close', () => resolve(buf.toString('utf8')));
          sock.on('error', reject);
        });

        expect(unauthResponse).toContain('FATAL');
        expect(unauthResponse).toContain('28P01');
        expect(mockClient.post).not.toHaveBeenCalled();

        // Case B: Client sends wrong password in 'p' PasswordMessage
        const wrongPwResponse = await new Promise<string>((resolve, reject) => {
          const sock = net.createConnection({ host: proxy.host, port: proxy.port }, () => {
            const startup = Buffer.alloc(8);
            startup.writeInt32BE(8, 0);
            startup.writeInt32BE(196608, 4);
            sock.write(startup);
          });

          let sentPw = false;
          let buf = Buffer.alloc(0);
          sock.on('data', (chunk: Buffer) => {
            buf = Buffer.concat([buf, chunk]);
            if (!sentPw && buf[0] === 0x52) {
              sentPw = true;
              const pwBytes = Buffer.from('wrong_password_attempt\0', 'utf8');
              const pMsg = Buffer.alloc(5 + pwBytes.length);
              pMsg[0] = 0x70; // 'p'
              pMsg.writeInt32BE(4 + pwBytes.length, 1);
              pwBytes.copy(pMsg, 5);
              sock.write(pMsg);
            }
          });
          sock.on('close', () => resolve(buf.toString('utf8')));
          sock.on('error', reject);
        });

        expect(wrongPwResponse).toContain('FATAL');
        expect(wrongPwResponse).toContain('28P01');
        expect(wrongPwResponse).toContain('password authentication failed');
        expect(mockClient.post).not.toHaveBeenCalled();
      } finally {
        await proxy.close();
      }
    });

    it('reads piped API key via --key-stdin, rejects oversized stdin (>4 KB), and rejects TTY stdin without a pipe', async () => {
      const { Readable } = await import('node:stream');
      const { readKeyFromStdin } = await import('../src/commands/login.js');

      // 1. Valid piped key via --key-stdin in login()
      const fetchMock = vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            orgId: 'org-stdin-test',
            orgName: 'Stdin Health Clinic',
            tier: 'active',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      );
      vi.stubGlobal('fetch', fetchMock);

      const pipedKey = 'hb_pat_stdinSecretKey1234567890';
      const stdinStream = Readable.from([`${pipedKey}\n`]);
      const code = await login(['--key-stdin'], {
        _argv: ['--key-stdin'],
        _stdin: stdinStream,
      });
      expect(code).toBe(0);
      expect(loadCredentials()?.apiKey).toBe(pipedKey);

      // 2. Oversized stdin (> 4096 bytes) is rejected before buffering unbounded memory
      const hugeStream = Readable.from(['hb_pat_' + 'A'.repeat(5000)]);
      await expect(readKeyFromStdin(hugeStream, 4096)).rejects.toThrow(
        /exceeded maximum allowed API key length/i,
      );

      // 3. Interactive TTY stdin with --key-stdin is rejected with actionable guidance
      const ttyStream = Object.assign(Readable.from(['']), { isTTY: true });
      await expect(readKeyFromStdin(ttyStream)).rejects.toThrow(
        /--key-stdin requires piping an API key/i,
      );
    });

    it('scrubs inline --key secrets from process.argv and resets process.title', async () => {
      const { scrubProcessArgvSecret } = await import('../src/commands/login.js');
      const inlineSecret = 'hb_live_inlineProcessArgvSecret999';
      const origArgv = [...process.argv];
      try {
        process.argv.push('--key', inlineSecret, `--key=${inlineSecret}`);
        scrubProcessArgvSecret(inlineSecret);

        expect(process.argv).not.toContain(inlineSecret);
        expect(process.argv.some((a) => a.includes(inlineSecret))).toBe(false);
        expect(process.argv).toContain('[REDACTED]');
        expect(process.argv).toContain('--key=[REDACTED]');
      } finally {
        process.argv = origArgv;
      }
    });
  });

  describe('S-14: CLI Code Review & Refactoring Verification', () => {
    it('correctly resolves defaultEnvId when flags with string values precede optional positionals (patients, query, logs)', async () => {
      saveCredentials({
        apiKey: 'hb_pat_validTestKey123456',
        orgId: 'org-1',
        orgName: 'Default Clinic',
        keyPrefix: 'hb_pat_validTe...',
        createdAt: new Date().toISOString(),
        defaultEnvId: 'env_default_clinic_99'
      });

      const getSpy = vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
        if (path.endsWith('/patients')) {
          return { environment_id: 'env_default_clinic_99', total: 0, patients: [] };
        }
        if (path.endsWith('/logs')) {
          return [];
        }
        return {};
      });
      const postSpy = vi.spyOn(api, 'post').mockResolvedValue({
        rows: [{ ok: 1 }],
        row_count: 1,
        columns: ['ok'],
        execution_time_ms: 2,
        bytes_egressed: 16
      });

      // 1. `hebrah env patients --department Cardiology` -> should NOT treat "Cardiology" as environment_id
      const patCode = await env(['patients', '--department', 'Cardiology'], {
        _argv: ['patients', '--department', 'Cardiology']
      });
      expect(patCode).toBe(0);
      expect(getSpy).toHaveBeenCalledWith(
        '/v1/environments/env_default_clinic_99/ehr/patients',
        expect.objectContaining({ department: 'Cardiology' })
      );

      // 2. `hebrah env query --sql "SELECT 1"` -> should NOT treat "SELECT 1" as environment_id
      const queryCode = await env(['query', '--sql', 'SELECT 1'], {
        _argv: ['query', '--sql', 'SELECT 1']
      });
      expect(queryCode).toBe(0);
      expect(postSpy).toHaveBeenCalledWith(
        '/v1/environments/env_default_clinic_99/db/query',
        expect.objectContaining({ sql: 'SELECT 1' })
      );

      // 3. `hebrah env logs --limit 5` -> should NOT treat "5" as environment_id
      const logsCode = await env(['logs', '--limit', '5'], {
        _argv: ['logs', '--limit', '5']
      });
      expect(logsCode).toBe(0);
      expect(getSpy).toHaveBeenCalledWith(
        '/v1/environments/env_default_clinic_99/logs',
        { limit: '5' }
      );
    });

    it('calculates visual column width excluding SGR ANSI escape codes and redacts secrets in table()', async () => {
      const { table, green, visibleLength } = await import('../src/output/format.js');
      const coloredActive = `\x1b[32mactive\x1b[0m`;
      expect(visibleLength(coloredActive)).toBe(6);
      expect(visibleLength(green('active'))).toBe(6);

      const lines: string[] = [];
      const logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
        lines.push(args.map(String).join(' '));
      });
      try {
        table(
          ['STATUS', 'NOTE'],
          [
            [coloredActive, 'Token hb_live_secretToken1234567890'],
            ['paused', 'Normal row']
          ]
        );
        // Header + separator + 2 data rows = 4 lines
        expect(lines.length).toBe(4);
        // Secret in table cell should be redacted
        expect(lines[2]).not.toContain('hb_live_secretToken1234567890');
        expect(lines[2]).toContain('[REDACTED_HEBRAH_TOKEN]');
        // Visual alignment: stripping SGR codes from row 1 and row 2 should place column 2 at the exact same index (8)
        const stripSgr = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');
        const col2IdxRow1 = stripSgr(lines[2]).indexOf('Token [REDACTED_HEBRAH_TOKEN]');
        const col2IdxRow2 = stripSgr(lines[3]).indexOf('Normal row');
        expect(col2IdxRow1).toBe(8);
        expect(col2IdxRow1).toBe(col2IdxRow2);
      } finally {
        logSpy.mockRestore();
      }
    });

    it('blocks IPv4-mapped IPv6 cloud metadata link-local addresses in isCloudMetadataHost and validateApiBaseUrl', async () => {
      const { isCloudMetadataHost, validateApiBaseUrl } = await import('../src/api/client.js');
      expect(isCloudMetadataHost('[::ffff:169.254.169.254]')).toBe(true);
      expect(isCloudMetadataHost('::ffff:a9fe:a9fe')).toBe(true);
      expect(() => validateApiBaseUrl('https://[::ffff:169.254.169.254]')).toThrow(
        /cloud metadata or link-local/i
      );
    });

    it('returns semantic exit codes and redacts secrets in handleCommandError', async () => {
      const { handleCommandError } = await import('../src/output/format.js');
      const { ApiError } = await import('../src/api/client.js');
      const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      try {
        expect(handleCommandError(new ApiError('Unauthorized key hb_pat_1234567890abcdef', 401))).toBe(2);
        expect(handleCommandError(new ApiError('Insufficient funds', 402, null, 'Run hebrah topup'))).toBe(5);
        expect(handleCommandError(new ApiError('Server error', 500))).toBe(4);
        const allErrors = errSpy.mock.calls.map((c) => String(c[0])).join('\n');
        expect(allErrors).not.toContain('hb_pat_1234567890abcdef');
        expect(allErrors).toContain('[REDACTED_HEBRAH_TOKEN]');
      } finally {
        errSpy.mockRestore();
      }
    });
  });

  describe('S-15: Fourth-Pass Security Sweep (Symlink/TOCTOU, Loopback Host Header, PG Pre-Auth Timeout, Skill & Env Sanitization)', () => {
    it('S-1: writeWireguardConfigFile rejects dangling symlinks, symlinked parent directories, and writes atomically with 0600 permissions', async () => {
      const { writeWireguardConfigFile } = await import('../src/util/wireguard.js');
      const { mkdirSync } = await import('node:fs');

      // 1. Dangling/broken symlink at target path (existsSync would return false, lstatSync catches it)
      const danglingLink = join(tempDir, 'dangling.conf');
      symlinkSync(join(tempDir, 'nonexistent-target.conf'), danglingLink);
      expect(() => writeWireguardConfigFile(danglingLink, '[Interface]\nPrivateKey = AAAA\n')).toThrow(
        /symlink|symbolic link/i
      );

      // 2. Symlinked parent directory
      const realDir = join(tempDir, 'real-dir');
      mkdirSync(realDir, { mode: 0o700 });
      const symlinkDir = join(tempDir, 'symlink-dir');
      symlinkSync(realDir, symlinkDir);
      expect(() =>
        writeWireguardConfigFile(join(symlinkDir, 'wg0.conf'), '[Interface]\nPrivateKey = AAAA\n')
      ).toThrow(/symlinked directory/i);

      // 3. Valid write creates 0o600 regular file atomically
      const validConf = join(realDir, 'hebrah-env.conf');
      const writtenPath = writeWireguardConfigFile(validConf, '[Interface]\nPrivateKey = AAAA\n');
      const st = statSync(writtenPath);
      expect(st.mode & 0o777).toBe(0o600);
    });

    it('S-2: hebrah query --file rejects symbolic links before reading file contents', async () => {
      const queryCmd = (await import('../src/commands/query.js')).default;
      const secretFile = join(tempDir, 'secret-target.sql');
      writeFileSync(secretFile, 'SELECT 1;');
      const symlinkSql = join(tempDir, 'link.sql');
      symlinkSync(secretFile, symlinkSql);

      const postSpy = vi.spyOn(api, 'post');
      const code = await queryCmd(['conn_123', '--file', symlinkSql]);
      expect(code).toBe(1);
      expect(postSpy).not.toHaveBeenCalled();
      const errOut = errorSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(errOut).toMatch(/symbolic link/i);
    });

    it('S-3: loopback auth server rejects missing or empty Host headers (HTTP/1.0 DNS rebinding bypass)', async () => {
      const { isValidLoopbackHostHeader, startLoopbackAuth } = await import('../src/util/loopback.js');
      const net = await import('node:net');

      expect(isValidLoopbackHostHeader(undefined)).toBe(false);
      expect(isValidLoopbackHostHeader('')).toBe(false);
      expect(isValidLoopbackHostHeader('   ')).toBe(false);
      expect(isValidLoopbackHostHeader('127.0.0.1:43210')).toBe(true);
      expect(isValidLoopbackHostHeader('localhost:43210')).toBe(true);

      const listener = await startLoopbackAuth();
      try {
        // Send raw HTTP/1.0 request with NO Host header
        const rawResp = await new Promise<string>((resolve, reject) => {
          const sock = net.createConnection({ host: '127.0.0.1', port: listener.port }, () => {
            sock.write(
              `GET /callback?apiKey=hb_pat_validkey12345678&state=${listener.state} HTTP/1.0\r\n\r\n`
            );
          });
          let data = '';
          sock.on('data', (chunk) => {
            data += chunk.toString('utf8');
          });
          sock.on('end', () => resolve(data));
          sock.on('error', reject);
        });
        expect(rawResp).toContain('403 Forbidden');
        expect(rawResp).toMatch(/invalid Host header/i);
      } finally {
        listener.close();
      }
    });

    it('S-4: startPgWireProxy disconnects idle pre-authentication sockets after preAuthTimeoutMs', async () => {
      const { startPgWireProxy } = await import('../src/util/pgProxy.js');
      const net = await import('node:net');

      const proxy = await startPgWireProxy({
        envId: 'env_s15_timeout',
        port: 0,
        preAuthTimeoutMs: 60
      });

      try {
        const closedQuickly = await new Promise<boolean>((resolve, reject) => {
          const startedAt = Date.now();
          const sock = net.createConnection({ host: proxy.host, port: proxy.port });
          sock.on('close', () => {
            resolve(Date.now() - startedAt < 1500);
          });
          sock.on('error', reject);
        });
        expect(closedQuickly).toBe(true);
      } finally {
        await proxy.close();
      }
    });

    it('S-5: hebrah skill honors --path and sanitizes/redacts live and bundled skill output', async () => {
      const skillCmd = (await import('../src/commands/skill.js')).default;
      const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

      try {
        // 1. `hebrah skill --path`
        const pathCode = await skillCmd(['--path'], { _argv: ['--path'] });
        expect(pathCode).toBe(0);
        const printedPath = String(logSpy.mock.calls.at(-1)?.[0] ?? '');
        expect(printedPath).toMatch(/skill\.md$/);

        // 2. `hebrah skill --refresh` sanitizes terminal escapes and redacts tokens
        const fetchMock = vi.fn().mockResolvedValue(
          new Response(
            '# Skill Doc\n\x1b]52;c;ZWNobyBoYWNrZWQ=\x07\x9b2JToken: hb_live_leakedSkillToken1234567890\n',
            { status: 200 }
          )
        );
        vi.stubGlobal('fetch', fetchMock);

        const refreshCode = await skillCmd([], { _argv: ['--refresh'] });
        expect(refreshCode).toBe(0);
        const written = writeSpy.mock.calls.map((c) => String(c[0])).join('');
        expect(written).not.toContain('\x1b]52');
        expect(written).not.toContain('\x9b');
        expect(written).not.toContain('hb_live_leakedSkillToken1234567890');
        expect(written).toContain('[REDACTED_HEBRAH_TOKEN]');
      } finally {
        writeSpy.mockRestore();
      }
    });

    it('S-6: hebrah env status and wireguard sanitize terminal escape sequences in direct console.log fields', async () => {
      vi.spyOn(api, 'get').mockResolvedValueOnce({
        id: 'env_sec_status',
        org_id: 'org_1',
        name: 'Clinic\x1b]52;c;evil\x07Name',
        clinic_type: 'ambulatory_clinic',
        patient_cohort: 'adult',
        status: 'active',
        addons: ['postgres'],
        patient_count: 10,
        bed_count: 5,
        endpoints: {},
        database_modules: [
          {
            type: 'postgres\x1b]52;c;evil\x07',
            status: 'ready\x9b2J',
            port: 5432,
            size_mb: 12,
            tables_count: 6
          }
        ],
        connected_agents: [
          {
            agent_id: 'ag_1\x1b]8;;https://evil.com\x07Click\x1b]8;;\x07',
            name: 'Agent\x9d52;c;evil\x07Bot',
            connected_at: '2026-10-18T00:00:00Z\x1b[2J'
          }
        ],
        queries_run: 1,
        bytes_egressed: 100,
        hourly_rate_cents: 5,
        total_cost_cents: 5,
        created_at: '2026-10-18T00:00:00Z'
      });

      const code = await env(['status', 'env_sec_status'], { _argv: ['status', 'env_sec_status'] });
      expect(code).toBe(0);

      const allOut = logSpy.mock.calls.map((c) => c.map(String).join(' ')).join('\n');
      expect(allOut).not.toContain(']52;');
      expect(allOut).not.toContain(']8;;');
      expect(allOut).not.toContain('\x1b[2J');
      expect(allOut).not.toContain('\x9b');
      expect(allOut).not.toContain('\x9d');
      expect(allOut).toContain('ClinicName');
      expect(allOut).toContain('AgentBot');
    });
  });
});
