import { describe, expect, it, vi, beforeEach } from 'vitest';
import env from '../src/commands/env.js';
import { api } from '../src/api/client.js';

describe('hebrah env command', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.restoreAllMocks();
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  describe('help and unknown commands', () => {
    it('shows help when no subcommands or --help passed', async () => {
      const code = await env([], { _argv: [] });
      expect(code).toBe(0);
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('hebrah env — manage isolated clinic environments'));
    });

    it('returns error code 1 on unknown subcommand', async () => {
      const code = await env(['foobar'], { _argv: ['foobar'] });
      expect(code).toBe(1);
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('unknown subcommand "foobar"'));
    });
  });

  describe('env list', () => {
    it('lists environments in formatted table by default', async () => {
      const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce({
        environments: [
          {
            id: 'env-test-1',
            org_id: 'org-test-1',
            name: 'Cardiology Clinic',
            clinic_type: 'cardiology_clinic',
            patient_cohort: 'geriatric',
            status: 'active',
            addons: ['postgres', 'neo4j'],
            patient_count: 50,
            bed_count: 30,
            endpoints: { fhir: 'http://localhost:8000/v1/environments/env-test-1/fhir' },
            wireguard_ip: '10.42.0.2',
            queries_run: 120,
            bytes_egressed: 45000,
            hourly_rate_cents: 20,
            total_cost_cents: 480,
            connected_agents_count: 1,
            last_active_at: '2026-10-13T12:00:00Z',
            created_at: '2026-10-13T10:00:00Z'
          }
        ]
      });

      const code = await env(['list'], { _argv: ['list'] });
      expect(code).toBe(0);
      expect(getSpy).toHaveBeenCalledWith('/v1/environments', {});
    });

    it('outputs JSON when --json is passed to list', async () => {
      vi.spyOn(api, 'get').mockResolvedValueOnce({
        environments: [
          {
            id: 'env-test-2',
            name: 'Pediatric Clinic',
            status: 'active',
            addons: ['postgres']
          }
        ]
      });

      const code = await env(['list', '--json'], { _argv: ['list', '--json'] });
      expect(code).toBe(0);
      const jsonCalls = logSpy.mock.calls.map((c) => c[0]);
      const matched = jsonCalls.find((call) => typeof call === 'string' && call.includes('env-test-2'));
      expect(matched).toBeDefined();
    });
  });

  describe('env create', () => {
    it('creates a new environment with default parameters', async () => {
      const postSpy = vi.spyOn(api, 'post').mockResolvedValueOnce({
        id: 'env-created-1',
        org_id: 'org-1',
        name: 'St. Jude Sandbox',
        clinic_type: 'general_clinic',
        patient_cohort: 'geriatric',
        status: 'active',
        addons: ['postgres'],
        patient_count: 25,
        bed_count: 40,
        endpoints: { fhir: 'http://localhost:8000/fhir', hl7_ws: 'ws://localhost:8000/hl7' },
        wireguard_ip: '10.42.0.3',
        queries_run: 0,
        bytes_egressed: 0,
        hourly_rate_cents: 10,
        total_cost_cents: 0,
        connected_agents_count: 0,
        created_at: '2026-10-13T12:00:00Z',
        connection_instructions: {},
        database_modules: [],
        connected_agents: []
      });

      const code = await env(['create', '--name', 'St. Jude Sandbox'], {
        _argv: ['create', '--name', 'St. Jude Sandbox']
      });
      expect(code).toBe(0);
      expect(postSpy).toHaveBeenCalledWith('/v1/environments', expect.objectContaining({
        name: 'St. Jude Sandbox',
        clinic_type: 'general_clinic',
        addons: ['postgres']
      }));
    });
  });

  describe('env status', () => {
    it('fails if environment_id is missing', async () => {
      const code = await env(['status'], { _argv: ['status'] });
      expect(code).toBe(1);
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('environment_id required'));
    });

    it('fetches and displays details for an environment', async () => {
      const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce({
        id: 'env-status-1',
        org_id: 'org-1',
        name: 'Metropolitan Hospital',
        clinic_type: 'hospital_system',
        patient_cohort: 'mixed',
        status: 'active',
        addons: ['postgres', 'vector_qdrant'],
        patient_count: 100,
        bed_count: 200,
        endpoints: { fhir: 'http://fhir.local', hl7_ws: 'ws://hl7.local' },
        wireguard_ip: '10.42.0.4',
        queries_run: 42,
        bytes_egressed: 1024,
        hourly_rate_cents: 20,
        total_cost_cents: 200,
        connected_agents_count: 2,
        created_at: '2026-10-13T09:00:00Z',
        database_modules: [
          { type: 'postgres', status: 'ready', port: 5432, size_mb: 24, tables_count: 14 }
        ],
        connected_agents: [
          { agent_id: 'ag-1', name: 'Clinical Researcher', connected_at: '2026-10-13T10:00:00Z' }
        ]
      });

      const code = await env(['status', 'env-status-1'], {
        _argv: ['status', 'env-status-1']
      });
      expect(code).toBe(0);
      expect(getSpy).toHaveBeenCalledWith('/v1/environments/env-status-1');
    });
  });

  describe('env pause and resume', () => {
    it('pauses an environment', async () => {
      const postSpy = vi.spyOn(api, 'post').mockResolvedValueOnce({
        id: 'env-pause-1',
        status: 'paused'
      });

      const code = await env(['pause', 'env-pause-1'], {
        _argv: ['pause', 'env-pause-1']
      });
      expect(code).toBe(0);
      expect(postSpy).toHaveBeenCalledWith('/v1/environments/env-pause-1/pause');
    });

    it('resumes an environment', async () => {
      const postSpy = vi.spyOn(api, 'post').mockResolvedValueOnce({
        id: 'env-resume-1',
        status: 'active'
      });

      const code = await env(['resume', 'env-resume-1'], {
        _argv: ['resume', 'env-resume-1']
      });
      expect(code).toBe(0);
      expect(postSpy).toHaveBeenCalledWith('/v1/environments/env-resume-1/resume');
    });
  });

  describe('env destroy', () => {
    it('destroys environment when --yes is supplied', async () => {
      const delSpy = vi.spyOn(api, 'delete').mockResolvedValueOnce({
        ok: true,
        id: 'env-del-1',
        status: 'destroyed'
      });

      const code = await env(['destroy', 'env-del-1', '--yes'], {
        _argv: ['destroy', 'env-del-1', '--yes']
      });
      expect(code).toBe(0);
      expect(delSpy).toHaveBeenCalledWith('/v1/environments/env-del-1');
    });
  });

  describe('env query', () => {
    it('requires environment_id and SQL', async () => {
      const code = await env(['query', 'env-1'], { _argv: ['query', 'env-1'] });
      expect(code).toBe(1);
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('SQL query required'));
    });

    it('executes credential-blind query on database handle', async () => {
      const postSpy = vi.spyOn(api, 'post').mockResolvedValueOnce({
        rows: [{ id: 'P-1', name: 'John Doe', age: 45 }],
        row_count: 1,
        bytes_egressed: 256,
        duration_ms: 8,
        sql_executed: 'SELECT * FROM patients LIMIT 1'
      });

      const code = await env(['query', 'env-1', 'SELECT * FROM patients LIMIT 1'], {
        _argv: ['query', 'env-1', 'SELECT * FROM patients LIMIT 1']
      });
      expect(code).toBe(0);
      expect(postSpy).toHaveBeenCalledWith('/v1/environments/env-1/db/query', {
        sql: 'SELECT * FROM patients LIMIT 1',
        addon: 'postgres',
        actor_type: 'agent'
      });
    });
  });

  describe('env wireguard', () => {
    it('fetches WireGuard configuration', async () => {
      const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce({
        environment_id: 'env-wg-1',
        client_ip: '10.42.0.2/32',
        server_endpoint: 'wireguard.hebrah.local:51820',
        config_text: '[Interface]\nPrivateKey = testkey\nAddress = 10.42.0.2/32'
      });

      const code = await env(['wireguard', 'env-wg-1'], {
        _argv: ['wireguard', 'env-wg-1']
      });
      expect(code).toBe(0);
      expect(getSpy).toHaveBeenCalledWith('/v1/environments/env-wg-1/wireguard/config');
    });
  });

  describe('env scenario', () => {
    it('triggers a synthetic clinical scenario', async () => {
      const postSpy = vi.spyOn(api, 'post').mockResolvedValueOnce({
        ok: true,
        scenario: 'admit_patient',
        hl7_message: 'MSH|^~\\&|SYNTH_EHR...',
        websocket_broadcast: true
      });

      const code = await env(['scenario', 'env-sc-1', '--type', 'admit_patient', '--patient-id', 'P-101'], {
        _argv: ['scenario', 'env-sc-1', '--type', 'admit_patient', '--patient-id', 'P-101']
      });
      expect(code).toBe(0);
      expect(postSpy).toHaveBeenCalledWith('/v1/environments/env-sc-1/clinic/scenarios', {
        scenario: 'admit_patient',
        patient_id: 'P-101',
        notes: undefined
      });
    });
  });

  describe('env db-proxy', () => {
    it('outputs developer database GUI connection coordinates', async () => {
      vi.spyOn(api, 'get').mockResolvedValueOnce({
        id: 'env-proxy-1',
        name: 'Proxy Clinic',
        wireguard_ip: '10.42.0.5'
      });

      const code = await env(['db-proxy', 'env-proxy-1', '--json'], {
        _argv: ['db-proxy', 'env-proxy-1', '--json']
      });
      expect(code).toBe(0);
      const jsonCalls = logSpy.mock.calls.map((c) => c[0]);
      const matched = jsonCalls.find((call) => typeof call === 'string' && call.includes('10.42.0.5'));
      expect(matched).toBeDefined();
    });
  });
});
