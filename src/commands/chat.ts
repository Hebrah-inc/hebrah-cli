// `hebrah chat` (alias: `hebrah onboard`) — Two-Stage Hosted Personal Concierge & Account/Environment Studio.
//
// Stage 1 (Onboarding Concierge):
//   - Works with zero pre-existing credentials (`hb_onb_<uuid>_<32hex>` session token saved at ~/.hebrah/concierge.json, mode 0600).
//   - Answers questions about Hebrah features, 16 clinical archetypes, 6 base clinical packs, 5 open-data packs, and functions.
//   - Synthesizes a custom environment blueprint from plain English.
//   - Supports all account creation & login paths:
//       1) Headless agent signup ($5.00 free credit) -> auto-saves ~/.hebrah/credentials (0600) & provisions environment
//       2) Agent signup + human email invite (--invite you@company.com) -> provisions & emails claim link
//       3) Existing human/agent login (--login browser loopback, --device RFC 8628, --key hb_conn_*) -> claims session via POST /v1/concierge/claim
//
// Stage 2 (Personal Account & Environment Studio Agent):
//   - Authenticated per-(org_id, agent_principal_id) isolated memory (AES-256-GCM enc:v2: with AAD).
//   - Runs credential-blind SQL, open-data joins, FHIR R4 search, DICOM PACS queries, HTI-5 clinical outcome write-backs,
//     3-mode SDK starter bundles (Node.js, Python, MCP, WireGuard), multi-environment switching, and human teammate invites.

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
import { join, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { api, safeId } from '../api/client.js';
import {
  hebrahDir,
  loadCredentials,
  saveCredentials,
  updateCredentials,
  isValidApiKeyFormat
} from '../config/credentials.js';
import {
  bold,
  cyan,
  dim,
  error,
  green,
  info,
  json,
  kv,
  redactSecrets,
  sanitizeTerminalText,
  success,
  table,
  yellow
} from '../output/format.js';
import { applyAuthUrlFlags, getArgv } from '../util/args.js';
import loginCommand, { scrubProcessArgvSecret } from './login.js';

export interface ConciergeLocalState {
  sessionId?: string;
  sessionToken?: string;
  stage?: string;
  activeEnvironmentId?: string;
  apiUrl?: string;
  updatedAt: string;
}

export function conciergeStatePath(): string {
  return join(hebrahDir(), 'concierge.json');
}

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

export function loadConciergeState(): ConciergeLocalState | null {
  const dir = hebrahDir();
  const filePath = conciergeStatePath();
  assertNotSymlink(dir);
  assertNotSymlink(filePath);
  if (!existsSync(filePath)) return null;
  try {
    const st = lstatSync(filePath);
    if (st.isSymbolicLink() || !st.isFile() || st.size > 65_536) {
      return null;
    }
    const raw = JSON.parse(readFileSync(filePath, 'utf-8'));
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    return raw as ConciergeLocalState;
  } catch {
    return null;
  }
}

export function saveConciergeState(state: ConciergeLocalState): void {
  const dir = hebrahDir();
  const filePath = conciergeStatePath();
  assertNotSymlink(dir);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  mkdirSync(dirname(filePath), { recursive: true, mode: 0o700 });
  assertNotSymlink(filePath);

  const tmpPath = `${filePath}.tmp.${process.pid}.${randomBytes(4).toString('hex')}`;
  try {
    writeFileSync(tmpPath, JSON.stringify(state, null, 2), { encoding: 'utf-8', mode: 0o600 });
    chmodSync(tmpPath, 0o600);
    renameSync(tmpPath, filePath);
    chmodSync(filePath, 0o600);
  } catch (err) {
    try {
      if (existsSync(tmpPath)) unlinkSync(tmpPath);
    } catch {
      // ignore
    }
    throw err;
  }
}

export function clearConciergeState(): void {
  const filePath = conciergeStatePath();
  assertNotSymlink(filePath);
  if (existsSync(filePath)) {
    unlinkSync(filePath);
  }
}

function showChatHelp(): void {
  console.log(`hebrah chat — Personal Onboarding Concierge & Account/Environment Studio Agent

Usage:
  hebrah chat "<message>" [options]
  hebrah onboard "<message>" [options]

Examples:
  # 1. Start or continue your Personal Concierge conversation (no account required)
  npx --yes @hebrah/cli@latest chat "What is Hebrah and what clinical datasets do you have?"
  npx --yes @hebrah/cli@latest chat "I'm building an ICU sepsis alert agent that monitors bedside vitals"

  # 2. Create a free agent account ($5.00 credit) + provision your environment in one turn
  npx --yes @hebrah/cli@latest chat "Create my free agent account and spin it up"

  # 3. Create an agent account + invite a human teammate to claim/adopt the org
  npx --yes @hebrah/cli@latest chat "Spin it up and invite founder@acmedigital.io"

  # 4. Log in with an existing Hebrah account and claim your pre-auth Concierge blueprint
  npx --yes @hebrah/cli@latest chat --login
  npx --yes @hebrah/cli@latest chat --device
  npx --yes @hebrah/cli@latest chat --key hb_conn_...

  # 5. Stage 2 Personal Studio: query patients, record HTI-5 outcomes, or generate SDK code
  npx --yes @hebrah/cli@latest chat "Query the first 5 patients in my environment"
  npx --yes @hebrah/cli@latest chat "Record a clinical outcome writeback risk score of 0.91 for pat-001"
  npx --yes @hebrah/cli@latest chat "Generate an SDK integration snippet to connect my code"

Options:
  --session <token_or_id>   Resume a specific Concierge token (hb_onb_*) or session UUID
  --new                     Start a fresh Concierge session
  --invite <email>          Invite a human teammate to claim/adopt the organization
  --env-id, --env <id>      Target or switch to a specific isolated environment ID
  --login                   Authenticate via browser OAuth and auto-claim current Concierge session
  --device, --headless      Authenticate via RFC 8628 Device Code and auto-claim current session
  --key <api_key>           Authenticate with an API key (hb_conn_* / hb_pat_*) and auto-claim
  --claim [hb_onb_*]        Claim a pre-auth Concierge session into your authenticated account
  --catalog                 Display the full Hebrah Concierge capability & dataset catalog
  --sessions                List your isolated Concierge & Studio sessions
  --api-url <url>           Override Hebrah API base URL (e.g. https://api.staging.hebrah.com)
  --app-url <url>           Override Hebrah App URL (e.g. https://app.staging.hebrah.com)
  --json                    Output structured JSON
  -h, --help                Show this help
`);
}

export default async function chat(
  args: string[],
  options: Record<string, unknown> = {}
): Promise<number> {
  const argv = getArgv(options, args);

  // Scrub any inline --key value from process.argv immediately
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === '--key' && typeof argv[i + 1] === 'string' && !argv[i + 1]!.startsWith('-')) {
      scrubProcessArgvSecret(argv[i + 1]!);
    } else if (token?.startsWith('--key=')) {
      scrubProcessArgvSecret(token.slice('--key='.length));
    }
  }

  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      prompt: { type: 'string' },
      message: { type: 'string', short: 'm' },
      session: { type: 'string', short: 's' },
      'session-id': { type: 'string' },
      'session-token': { type: 'string' },
      new: { type: 'boolean', default: false },
      invite: { type: 'string' },
      'org-name': { type: 'string' },
      'agent-name': { type: 'string' },
      action: { type: 'string' },
      'account-mode': { type: 'string' },
      'env-id': { type: 'string' },
      env: { type: 'string' },
      login: { type: 'boolean', default: false },
      device: { type: 'boolean', default: false },
      headless: { type: 'boolean', default: false },
      key: { type: 'string' },
      'key-stdin': { type: 'boolean', default: false },
      claim: { type: 'string' },
      catalog: { type: 'boolean', default: false },
      sessions: { type: 'boolean', default: false },
      'api-url': { type: 'string' },
      'app-url': { type: 'string' },
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false }
    },
    allowPositionals: true,
    strict: false
  });

  if (values.help) {
    showChatHelp();
    return 0;
  }

  const rawEnvId =
    typeof values['env-id'] === 'string'
      ? values['env-id']
      : typeof values.env === 'string'
        ? values.env
        : undefined;

  applyAuthUrlFlags({
    appUrl: typeof values['app-url'] === 'string' ? values['app-url'] : undefined,
    apiUrl: typeof values['api-url'] === 'string' ? values['api-url'] : undefined,
    envId: rawEnvId,
    inferFromResolvedAppUrl: true
  });

  if (values.new) {
    clearConciergeState();
  }

  // ---------------------------------------------------------------------------
  // 1. Optional Catalog Mode (`hebrah chat --catalog`)
  // ---------------------------------------------------------------------------
  if (values.catalog) {
    try {
      const cat = await api.get<Record<string, unknown>>('/v1/concierge/catalog');
      if (values.json) {
        json(cat);
        return 0;
      }
      const platform = (cat.platform ?? {}) as Record<string, unknown>;
      const archetypes = Array.isArray(cat.archetypes) ? (cat.archetypes as Array<Record<string, unknown>>) : [];
      const packs = Array.isArray(cat.base_clinical_packs) ? (cat.base_clinical_packs as Array<Record<string, unknown>>) : [];
      const openData = Array.isArray(cat.open_data_packs) ? (cat.open_data_packs as Array<Record<string, unknown>>) : [];
      console.log(bold(`${String(platform.name ?? 'Hebrah')} — ${String(platform.tagline ?? 'Isolated Health Environments')}`));
      console.log(dim(String(platform.summary ?? '')));
      console.log();
      kv([
        ['Clinical Archetypes', `${archetypes.length} hospital & specialty cohorts`],
        ['Base Clinical Packs', packs.map((p) => String(p.id ?? p.name ?? '')).join(', ')],
        ['Open-Data Packs', openData.map((p) => `${p.id} (${p.records})`).join(', ')],
        ['Free Trial Credit', '$5.00 (1,000 queries, 50 MB egress, 14-day TTL)']
      ]);
      return 0;
    } catch (err) {
      error((err as Error).message);
      return 1;
    }
  }

  // ---------------------------------------------------------------------------
  // 2. Optional Sessions List Mode (`hebrah chat --sessions`)
  // ---------------------------------------------------------------------------
  if (values.sessions) {
    try {
      const res = await api.get<{ sessions?: Array<Record<string, unknown>> }>('/v1/concierge/sessions');
      const list = Array.isArray(res.sessions) ? res.sessions : [];
      if (values.json) {
        json(res);
        return 0;
      }
      if (list.length === 0) {
        console.log(dim('No isolated Concierge or Studio sessions found for this principal.'));
        return 0;
      }
      const headers = ['SESSION ID', 'STAGE', 'STATUS', 'INTENT', 'TURNS', 'ENVIRONMENT ID'];
      const rows = list.map((s) => [
        String(s.session_id ?? ''),
        String(s.stage ?? ''),
        String(s.status ?? ''),
        String(s.build_intent_category ?? 'general'),
        String(s.turn_count ?? 0),
        String(s.active_environment_id ?? 'none')
      ]);
      table(headers, rows);
      return 0;
    } catch (err) {
      error((err as Error).message);
      return 1;
    }
  }

  // ---------------------------------------------------------------------------
  // 3. Optional Login Handoff (`--login`, `--device`, `--key`, `--key-stdin`)
  // ---------------------------------------------------------------------------
  const wantsLoginFlow =
    Boolean(values.login) ||
    Boolean(values.device) ||
    Boolean(values.headless) ||
    typeof values.key === 'string' ||
    Boolean(values['key-stdin']);

  if (wantsLoginFlow) {
    const loginArgs: string[] = [];
    if (values.device || values.headless) loginArgs.push('--headless');
    if (typeof values.key === 'string') loginArgs.push('--key', values.key);
    if (values['key-stdin']) loginArgs.push('--key-stdin');
    if (rawEnvId) loginArgs.push('--env-id', rawEnvId);
    if (typeof values['api-url'] === 'string') loginArgs.push('--api-url', values['api-url']);
    if (typeof values['app-url'] === 'string') loginArgs.push('--app-url', values['app-url']);

    const code = await loginCommand(loginArgs, { _argv: loginArgs });
    if (code !== 0) {
      return code;
    }
  }

  // ---------------------------------------------------------------------------
  // 4. Resolve Saved Concierge State & Auto-Claim if Newly Authenticated
  // ---------------------------------------------------------------------------
  const savedState = loadConciergeState();
  const explicitSessionArg =
    typeof values.session === 'string'
      ? values.session.trim()
      : typeof values['session-token'] === 'string'
        ? values['session-token'].trim()
        : typeof values['session-id'] === 'string'
          ? values['session-id'].trim()
          : undefined;

  let sessionToken =
    explicitSessionArg && explicitSessionArg.startsWith('hb_onb_')
      ? explicitSessionArg
      : savedState?.sessionToken;
  let sessionId =
    explicitSessionArg && !explicitSessionArg.startsWith('hb_onb_')
      ? explicitSessionArg
      : savedState?.sessionId;

  const explicitClaimToken =
    typeof values.claim === 'string' && values.claim.trim().startsWith('hb_onb_')
      ? values.claim.trim()
      : process.argv.includes('--claim')
        ? sessionToken
        : undefined;

  const creds = loadCredentials();
  const hasAuth = Boolean(creds?.apiKey || process.env.HEBRAH_API_KEY);

  if (hasAuth && (explicitClaimToken || (wantsLoginFlow && sessionToken))) {
    const tokenToClaim = explicitClaimToken ?? sessionToken!;
    try {
      const claimRes = await api.post<Record<string, unknown>>('/v1/concierge/claim', {
        session_token: tokenToClaim,
        provision_blueprint: true
      });
      sessionId = typeof claimRes.session_id === 'string' ? claimRes.session_id : sessionId;
      const activeEnv =
        typeof claimRes.active_environment_id === 'string'
          ? claimRes.active_environment_id
          : undefined;
      if (activeEnv) {
        try {
          updateCredentials({ defaultEnvId: activeEnv });
        } catch {
          // ignore
        }
      }
      saveConciergeState({
        sessionId,
        sessionToken: undefined,
        stage: String(claimRes.stage ?? 'environment_studio'),
        activeEnvironmentId: activeEnv,
        apiUrl: api.getBaseUrl(),
        updatedAt: new Date().toISOString()
      });
      if (values.json && positionals.length === 0 && !values.prompt && !values.message) {
        json(claimRes);
        return 0;
      }
      if (!values.json) {
        success(
          `Claimed your pre-auth Concierge blueprint into organization ${bold(String(claimRes.org_id ?? creds?.orgName ?? 'authenticated'))}`
        );
        if (activeEnv) {
          info(`Active isolated environment: ${bold(activeEnv)}`);
        }
      }
      if (positionals.length === 0 && !values.prompt && !values.message) {
        return 0;
      }
    } catch (err) {
      if (explicitClaimToken) {
        error(`Failed to claim Concierge session: ${(err as Error).message}`);
        return 1;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // 5. Execute Conversational Turn (`POST /v1/concierge/chat`)
  // ---------------------------------------------------------------------------
  const rawMessage =
    typeof values.prompt === 'string'
      ? values.prompt
      : typeof values.message === 'string'
        ? values.message
        : positionals.join(' ').trim();

  const message =
    rawMessage ||
    'Hi! Tell me what we can build on Hebrah and help me design my isolated clinical environment.';

  const body: Record<string, unknown> = {
    message,
    auto_run_tools: true
  };
  if (sessionId) body.session_id = sessionId;
  if (sessionToken) body.session_token = sessionToken;
  if (typeof values.invite === 'string' && values.invite.trim()) {
    body.invite_email = values.invite.trim();
  }
  if (typeof values['org-name'] === 'string' && values['org-name'].trim()) {
    body.org_name = values['org-name'].trim();
  }
  if (typeof values['agent-name'] === 'string' && values['agent-name'].trim()) {
    body.agent_name = values['agent-name'].trim();
  }
  if (typeof values.action === 'string' && values.action.trim()) {
    body.action = values.action.trim();
  }
  if (typeof values['account-mode'] === 'string' && values['account-mode'].trim()) {
    body.account_mode = values['account-mode'].trim();
  }
  if (rawEnvId) {
    body.target_environment_id = safeId(rawEnvId, 'env-id');
  }

  try {
    const res = await api.post<Record<string, unknown>>('/v1/concierge/chat', body);

    const returnedSessionId = typeof res.session_id === 'string' ? res.session_id : sessionId;
    const returnedToken =
      typeof res.session_token === 'string' ? res.session_token : sessionToken;
    const returnedStage = typeof res.stage === 'string' ? res.stage : 'onboarding_concierge';
    const activeEnvId =
      typeof res.active_environment_id === 'string'
        ? res.active_environment_id
        : savedState?.activeEnvironmentId;

    // If Stage 1 provisioned a new headless agent account, persist one_time_credentials to ~/.hebrah/credentials (0600)
    const oneTimeCreds = res.one_time_credentials as Record<string, unknown> | undefined;
    if (
      oneTimeCreds &&
      typeof oneTimeCreds.api_key === 'string' &&
      isValidApiKeyFormat(oneTimeCreds.api_key)
    ) {
      const newKey = oneTimeCreds.api_key;
      const orgIdStr = String(oneTimeCreds.org_id ?? res.org_id ?? '');
      const keyPrefixStr = String(oneTimeCreds.key_prefix ?? newKey.slice(0, 14));
      saveCredentials({
        apiKey: newKey,
        orgId: orgIdStr,
        orgName: typeof values['org-name'] === 'string' ? values['org-name'] : 'Hebrah Agent Lab',
        keyPrefix: keyPrefixStr,
        createdAt: new Date().toISOString(),
        apiUrl: api.getBaseUrl(),
        defaultEnvId: activeEnvId,
        claimUrl: typeof oneTimeCreds.claim_url === 'string' ? oneTimeCreds.claim_url : undefined
      });
    } else if (activeEnvId) {
      try {
        updateCredentials({ defaultEnvId: activeEnvId });
      } catch {
        // ignore if unauthenticated
      }
    }

    // Persist Concierge session continuity to ~/.hebrah/concierge.json (0600)
    saveConciergeState({
      sessionId: returnedSessionId,
      sessionToken: returnedStage === 'onboarding_concierge' ? returnedToken : undefined,
      stage: returnedStage,
      activeEnvironmentId: activeEnvId,
      apiUrl: api.getBaseUrl(),
      updatedAt: new Date().toISOString()
    });

    if (values.json) {
      json(res);
      return 0;
    }

    const stageBanner =
      returnedStage === 'environment_studio'
        ? `${bold(cyan('Hebrah Personal Environment Studio'))} ${dim(`(Stage 2 · ${activeEnvId ?? 'authenticated'})`)}`
        : `${bold(cyan('Hebrah Personal Onboarding Concierge'))} ${dim('(Stage 1 · Pre-Auth Sandbox Architect)')}`;

    console.log(stageBanner);
    console.log(dim('──────────────────────────────────────────────────────────────────'));
    const assistantMsg = redactSecrets(
      sanitizeTerminalText(String(res.assistant_message ?? res.reply ?? ''))
    );
    console.log(assistantMsg);
    console.log(dim('──────────────────────────────────────────────────────────────────'));

    const bp = (res.synthesized_blueprint ?? {}) as Record<string, unknown>;
    const toolsInvoked = Array.isArray(res.tools_invoked) ? (res.tools_invoked as string[]) : [];

    const summaryRows: Array<[string, string]> = [
      ['Session ID', String(returnedSessionId ?? 'n/a')],
      ['Stage', returnedStage === 'environment_studio' ? green('Stage 2 — Account & Environment Studio') : yellow('Stage 1 — Onboarding Concierge')]
    ];

    if (bp.archetype) {
      summaryRows.push([
        'Blueprint',
        `${String(bp.name ?? bp.archetype)} (${String(bp.archetype)}, ${String(bp.patient_count ?? 25)} patients)`
      ]);
    }
    if (activeEnvId) {
      summaryRows.push(['Active Environment', activeEnvId]);
    }
    if (toolsInvoked.length > 0) {
      summaryRows.push(['Tools Executed', toolsInvoked.join(', ')]);
    }
    if (res.wallet_paused) {
      summaryRows.push(['Wallet Status', yellow('Paused ($0.00 balance — data preserved)')]);
    }

    kv(summaryRows);

    if (oneTimeCreds && typeof oneTimeCreds.api_key === 'string') {
      console.log();
      success('Saved your new agent API key to ~/.hebrah/credentials (mode 0600) with $5.00 free trial credit.');
      if (typeof oneTimeCreds.claim_url === 'string') {
        info(`Human Claim & Adoption Link: ${bold(sanitizeTerminalText(oneTimeCreds.claim_url))}`);
      }
    }

    const humanInvite = res.human_invite as Record<string, unknown> | undefined;
    if (humanInvite && typeof humanInvite.claim_url === 'string') {
      console.log();
      info(
        `Human Claim Link (${sanitizeTerminalText(String(humanInvite.invited_email ?? 'teammate'))}): ${bold(sanitizeTerminalText(humanInvite.claim_url))}`
      );
    }

    const nextPrompts = Array.isArray(res.suggested_next_prompts)
      ? (res.suggested_next_prompts as string[])
      : Array.isArray(res.suggested_actions)
        ? (res.suggested_actions as string[])
        : [];
    if (nextPrompts.length > 0) {
      console.log();
      console.log(dim('Try next:'));
      for (const item of nextPrompts.slice(0, 3)) {
        console.log(dim(`  • npx @hebrah/cli chat "${sanitizeTerminalText(String(item))}"`));
      }
    }

    return 0;
  } catch (err) {
    error((err as Error).message);
    return 1;
  }
}
