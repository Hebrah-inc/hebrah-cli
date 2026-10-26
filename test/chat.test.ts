import { describe, expect, it, vi, beforeEach } from 'vitest';
import { rmSync } from 'node:fs';
import chat, { loadConciergeState } from '../src/commands/chat.js';
import { loadCredentials } from '../src/config/credentials.js';
import { api } from '../src/api/client.js';

describe('hebrah chat / onboard command', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  const testDir = '/tmp/hebrah-cli-concierge-test';

  beforeEach(() => {
    vi.restoreAllMocks();
    process.env.HEBRAH_CREDENTIALS_DIR = testDir;
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  it('persists Stage 1 session_token in ~/.hebrah/concierge.json and reuses it on turn 2', async () => {
    const postSpy = vi
      .spyOn(api, 'post')
      .mockResolvedValueOnce({
        session_id: '11111111-1111-1111-1111-111111111111',
        session_token: 'hb_onb_11111111-1111-1111-1111-111111111111_abcdef1234567890abcdef1234567890',
        stage: 'onboarding_concierge',
        status: 'active',
        synthesized_blueprint: {
          archetype: 'icu_critical_care',
          name: 'ICU Sepsis Sandbox',
          patient_count: 25,
          addons: ['postgres']
        },
        assistant_message: 'Awesome! I put together an ICU Critical Care blueprint for you.'
      })
      .mockResolvedValueOnce({
        session_id: '11111111-1111-1111-1111-111111111111',
        stage: 'environment_studio',
        status: 'converted',
        org_id: '22222222-2222-2222-2222-222222222222',
        active_environment_id: '33333333-3333-3333-3333-333333333333',
        one_time_credentials: {
          api_key: 'hb_conn_testconciergekey1234567890',
          key_prefix: 'hb_conn_testco',
          org_id: '22222222-2222-2222-2222-222222222222',
          trial_credit_usd: '5.00',
          claim_url: 'https://app.hebrah.com/claim-org/tok_123'
        },
        assistant_message: 'Your ICU Sepsis Sandbox is live with $5.00 free credit!'
      });

    // Turn 1: Pre-auth blueprint design
    const c1 = await chat(['I am building an ICU sepsis alert agent'], {
      _argv: ['I am building an ICU sepsis alert agent']
    });
    expect(c1).toBe(0);
    const state1 = loadConciergeState();
    expect(state1?.sessionToken).toContain('hb_onb_');
    expect(state1?.stage).toBe('onboarding_concierge');

    // Turn 2: Create free agent account -> automatically sends saved session_token and saves ~/.hebrah/credentials
    const c2 = await chat(['Create my free agent account and spin it up'], {
      _argv: ['Create my free agent account and spin it up']
    });
    expect(c2).toBe(0);
    expect(postSpy).toHaveBeenNthCalledWith(
      2,
      '/v1/concierge/chat',
      expect.objectContaining({
        session_id: '11111111-1111-1111-1111-111111111111',
        session_token: 'hb_onb_11111111-1111-1111-1111-111111111111_abcdef1234567890abcdef1234567890'
      })
    );

    const savedCreds = loadCredentials();
    expect(savedCreds?.apiKey).toBe('hb_conn_testconciergekey1234567890');
    expect(savedCreds?.defaultEnvId).toBe('33333333-3333-3333-3333-333333333333');
    const state2 = loadConciergeState();
    expect(state2?.stage).toBe('environment_studio');
  });

  it('fetches and displays the Concierge catalog with --catalog', async () => {
    const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce({
      platform: {
        name: 'Hebrah',
        tagline: 'Isolated Health Environments',
        summary: 'Private hospital sandboxes'
      },
      archetypes: [{ id: 'cardiology_center', name: 'Cardiology Center' }],
      base_clinical_packs: [{ id: 'fhir_r4', name: 'FHIR R4' }],
      open_data_packs: [{ id: 'clinical_knowledge_v1', records: 120 }]
    });

    const code = await chat(['--catalog'], { _argv: ['--catalog'] });
    expect(code).toBe(0);
    expect(getSpy).toHaveBeenCalledWith('/v1/concierge/catalog');
    expect(logSpy).toHaveBeenCalled();
  });
});
