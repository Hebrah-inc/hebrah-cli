import { describe, expect, it, vi, beforeEach } from 'vitest';
import env from '../src/commands/env.js';
import { api } from '../src/api/client.js';

describe('hebrah env command', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.restoreAllMocks();
    process.env.HEBRAH_CREDENTIALS_DIR = '/tmp/hebrah-cli-empty-env-test';
    delete process.env.HEBRAH_ENV_ID;
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

  describe('env info (alias for status)', () => {
    it('routes info subcommand to statusEnv', async () => {
      const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce({
        id: 'env-info-1',
        org_id: 'org-1',
        name: 'Info Clinic',
        clinic_type: 'ambulatory_clinic',
        patient_cohort: 'adult_primary',
        status: 'active',
        addons: ['postgres'],
        patient_count: 25,
        bed_count: 10,
        endpoints: { fhir: 'http://fhir.local' },
        wireguard_ip: '10.42.0.9',
        queries_run: 5,
        bytes_egressed: 512,
        hourly_rate_cents: 10,
        total_cost_cents: 50,
        connected_agents_count: 0,
        created_at: '2026-10-17T00:00:00Z'
      });

      const code = await env(['info', 'env-info-1'], {
        _argv: ['info', 'env-info-1']
      });
      expect(code).toBe(0);
      expect(getSpy).toHaveBeenCalledWith('/v1/environments/env-info-1');
    });
  });

  describe('env tables', () => {
    it('fetches PostgreSQL schema tables and row counts', async () => {
      const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce({
        environment_id: 'env-tab-1',
        schema: 'env_123456',
        table_count: 2,
        total_rows: 175,
        tables: [
          { table_name: 'patients', row_count: 50, columns: [{ name: 'id', type: 'text' }] },
          { table_name: 'observations', row_count: 125, columns: [{ name: 'id', type: 'text' }] }
        ]
      });

      const code = await env(['tables', 'env-tab-1'], {
        _argv: ['tables', 'env-tab-1']
      });
      expect(code).toBe(0);
      expect(getSpy).toHaveBeenCalledWith('/v1/environments/env-tab-1/db/tables');
    });
  });

  describe('env patients and admit', () => {
    it('lists synthetic patients in environment EHR', async () => {
      const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce([
        {
          id: 'P-1001',
          mrn: 'MRN-1001',
          first_name: 'Elena',
          last_name: 'Rostova',
          age: 64,
          gender: 'F',
          department: 'Cardiology',
          acuity: 'urgent',
          primary_diagnosis: 'I48.91 Atrial fibrillation'
        }
      ]);

      const code = await env(['patients', 'env-pat-1', '--department', 'Cardiology'], {
        department: 'Cardiology',
        _argv: ['patients', 'env-pat-1', '--department', 'Cardiology']
      });
      expect(code).toBe(0);
      expect(getSpy).toHaveBeenCalledWith('/v1/environments/env-pat-1/ehr/patients', {
        department: 'Cardiology'
      });
    });

    it('admits synthetic patients into environment EHR', async () => {
      const postSpy = vi.spyOn(api, 'post').mockResolvedValueOnce({
        ok: true,
        environment_id: 'env-pat-1',
        admitted_count: 5,
        total_patients: 55,
        new_patient_ids: ['P-1002', 'P-1003']
      });

      const code = await env(['admit', 'env-pat-1', '--count', '5', '--department', 'ICU'], {
        count: '5',
        department: 'ICU',
        _argv: ['admit', 'env-pat-1', '--count', '5', '--department', 'ICU']
      });
      expect(code).toBe(0);
      expect(postSpy).toHaveBeenCalledWith('/v1/environments/env-pat-1/ehr/patients/generate', {
        count: 5,
        departments: ['ICU']
      });
    });
  });

  describe('env logs', () => {
    it('fetches tamper-evident environment audit logs', async () => {
      const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce([
        {
          id: 'log-1',
          environment_id: 'env-log-1',
          actor_type: 'agent',
          actor_id: 'ag-1',
          event_type: 'db.query',
          query_text: 'SELECT count(*) FROM patients',
          rows_returned: 1,
          duration_ms: 4,
          status: 'success',
          event_hash: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
          created_at: '2026-10-17T12:00:00Z'
        }
      ]);

      const code = await env(['logs', 'env-log-1', '--limit', '10'], {
        limit: '10',
        _argv: ['logs', 'env-log-1', '--limit', '10']
      });
      expect(code).toBe(0);
      expect(getSpy).toHaveBeenCalledWith('/v1/environments/env-log-1/logs', {
        limit: '10'
      });
    });
  });

  describe('env studio', () => {
    it('sends a prompt to the Environment AI Studio assistant', async () => {
      const postSpy = vi.spyOn(api, 'post').mockResolvedValueOnce({
        session_id: 'sess-studio-1',
        environment_id: 'env-stu-1',
        schema_name: 'env_stu_1',
        reply: 'There are 12 high-acuity cardiology patients matching CHA2DS2-VASc >= 2.',
        tools_invoked: [
          { tool: 'sql_cohort_summary', status: 'ok', summary: 'Queried 50 patients in env_stu_1' }
        ],
        open_data_packs_queried: ['clinical_knowledge_v1', 'dicom_imaging_v1'],
        guardrail_triggered: false
      });

      const code = await env(['studio', 'env-stu-1', 'Analyze AFib stroke risk across cohort'], {
        _argv: ['studio', 'env-stu-1', 'Analyze AFib stroke risk across cohort']
      });
      expect(code).toBe(0);
      expect(postSpy).toHaveBeenCalledWith('/v1/environments/env-stu-1/studio/chat', {
        message: 'Analyze AFib stroke risk across cohort',
        auto_run_tools: true
      });
    });
  });

  describe('env open-data', () => {
    it('queries the Open-Data Enrichment Pack catalog', async () => {
      const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce({
        environment_id: 'env-od-1',
        environment_name: 'Cardiology Research Center',
        schema_name: 'env_od_1',
        clinical_knowledge_pack: {
          pack_id: 'clinical_knowledge_v1',
          version: '1.0.0',
          total_records: 24,
          subpacks: [
            {
              subpack_id: 'clinical_calculators',
              title: 'Clinical Risk Calculators (CC0)',
              license: 'CC0-1.0',
              record_count: 8
            }
          ],
          sample_records: [
            {
              id: 'calc_cha2ds2_vasc',
              subpack: 'clinical_calculators',
              title: 'CHA2DS2-VASc Score for Atrial Fibrillation Stroke Risk',
              specialty: 'cardiology',
              license: 'CC0-1.0'
            }
          ]
        },
        dicom_imaging_pack: {
          pack_id: 'dicom_imaging_v1',
          total_studies: 6,
          modalities: ['CT', 'MR', 'CR']
        }
      });

      const code = await env(['open-data', 'env-od-1', '--specialty', 'cardiology'], {
        specialty: 'cardiology',
        _argv: ['open-data', 'env-od-1', '--specialty', 'cardiology']
      });
      expect(code).toBe(0);
      expect(getSpy).toHaveBeenCalledWith('/v1/environments/env-od-1/open-data/catalog', {
        specialty: 'cardiology'
      });
    });
  });

  describe('env architect', () => {
    it('consults the Conversational Environment Architect', async () => {
      const postSpy = vi.spyOn(api, 'post').mockResolvedValueOnce({
        session_id: 'arch-sess-1',
        assistant_reply: 'I have designed a 120-bed Cardiology & Electrophysiology blueprint.',
        scope_status: 'in_scope',
        blueprint: {
          recommended_name: 'Heart Rhythm Sandbox',
          archetype_id: 'cardiology_center',
          patient_count: 75,
          bed_count: 120,
          addons: ['postgres', 'vector_qdrant'],
          estimated_hourly_cents: 15
        }
      });

      const code = await env(['architect', 'Design a cardiology AFib research hospital'], {
        _argv: ['architect', 'Design a cardiology AFib research hospital']
      });
      expect(code).toBe(0);
      expect(postSpy).toHaveBeenCalledWith('/v1/environments/architect/chat', {
        message: 'Design a cardiology AFib research hospital',
        auto_provision: false
      });
    });
  });
});

