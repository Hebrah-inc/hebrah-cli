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
          cli_version: '0.4.2'
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
  });
});

