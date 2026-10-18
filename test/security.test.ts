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
          cli_version: '0.4.3'
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
      expect(() => resolveAppUrl('https://169.254.169.254')).toThrow(/untrusted Hebrah host/i);
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
});

