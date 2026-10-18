// `hebrah wallet` — view balance, auto-reload config, burn rate, and runway.
//
// Usage:
//   hebrah wallet                              (view wallet)
//   hebrah wallet --auto-reload on             (enable with defaults: $5 threshold / $20 reload)
//   hebrah wallet --auto-reload on --threshold 300 --amount 2500
//   hebrah wallet --auto-reload off            (disable)
//   hebrah wallet --json                       (raw JSON output)

import { parseArgs } from 'node:util';
import { api, ApiError } from '../api/client.js';
import { loadCredentials } from '../config/credentials.js';
import { json, success, info, error, bold, dim, yellow, sanitizeTerminalText } from '../output/format.js';
import { getArgv } from '../util/args.js';

interface WalletView {
  org_id: string;
  tier: string;
  balance_cents: number;
  auto_reload: {
    enabled: boolean;
    threshold_cents: number | null;
    amount_cents: number | null;
    stripe_customer_linked: boolean;
  };
  burn_30d: {
    window_days: number;
    queries: number;
    cost_cents: number;
    avg_cost_per_query_cents: number;
  };
  projected_days_to_empty: number | null;
  trial?: {
    queries: number;
    egress_bytes: number;
    expires_at: string | null;
  };
}

interface WalletConfigResult {
  auto_reload?: {
    enabled: boolean;
    threshold_cents: number | null;
    amount_cents: number | null;
  };
  [key: string]: unknown;
}

export default async function wallet(
  _args: string[],
  options: Record<string, unknown> = {}
): Promise<number> {
  const argv = getArgv(options, _args);
  const { values } = parseArgs({
    args: argv,
    options: {
      'auto-reload': { type: 'string' },
      threshold: { type: 'string' },
      amount: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  const creds = loadCredentials();
  if (!creds && !process.env.HEBRAH_API_KEY) {
    error('Not logged in. Run `hebrah signup` or `hebrah login` first.');
    return 2;
  }

  try {
    // Config update (--auto-reload on|off)
    if (values['auto-reload'] !== undefined) {
      const mode = (values['auto-reload'] as string).toLowerCase();
      if (mode !== 'on' && mode !== 'off') {
        error('--auto-reload must be "on" or "off".');
        return 1;
      }
      const body: Record<string, unknown> = { auto_reload_enabled: mode === 'on' };
      if (values.threshold !== undefined) {
        const thresholdCents = parseInt(values.threshold as string, 10);
        if (!Number.isFinite(thresholdCents) || thresholdCents < 100 || thresholdCents > 1_000_000) {
          error('--threshold must be between 100 ($1.00) and 1000000 ($10,000.00) cents.');
          return 1;
        }
        body.auto_reload_threshold_cents = thresholdCents;
      }
      if (values.amount !== undefined) {
        const amountCents = parseInt(values.amount as string, 10);
        if (!Number.isFinite(amountCents) || amountCents < 100 || amountCents > 1_000_000) {
          error('--amount must be between 100 ($1.00) and 1000000 ($10,000.00) cents.');
          return 1;
        }
        body.auto_reload_amount_cents = amountCents;
      }
      const result = await api.post<WalletConfigResult>('/v1/agent/wallet/config', body);
      if (values.json || options.json) {
        json(result);
        return 0;
      }
      success(`Auto-reload ${mode}.`);
      if (result.auto_reload) {
        info(`  Threshold: $${((result.auto_reload.threshold_cents ?? 500) / 100).toFixed(2)}`);
        info(`  Reload amount: ${bold(`$${((result.auto_reload.amount_cents ?? 2000) / 100).toFixed(2)}`)}`);
      }
      if (mode === 'on') {
        info(dim('When your balance drops below the threshold, hebrah charges your saved card automatically.'));
      }
      return 0;
    }

    // Default: wallet view
    const walletData = await api.get<WalletView>('/v1/agent/wallet');
    if (values.json || options.json) {
      json(walletData);
      return 0;
    }

    console.log();
    console.log(`${bold('Wallet')} — ${sanitizeTerminalText(walletData.tier)} tier`);
    console.log(`  Balance: ${bold(`$${(walletData.balance_cents / 100).toFixed(2)}`)}`);
    console.log();
    console.log(`  Auto-reload: ${walletData.auto_reload.enabled ? bold('on') : dim('off')}`);
    if (walletData.auto_reload.enabled) {
      console.log(`    Threshold: $${((walletData.auto_reload.threshold_cents ?? 500) / 100).toFixed(2)}`);
      console.log(`    Reload: $${((walletData.auto_reload.amount_cents ?? 2000) / 100).toFixed(2)}`);
      console.log(
        `    Card: ${
          walletData.auto_reload.stripe_customer_linked
            ? dim('linked')
            : yellow('not linked (add a payment method via dashboard)')
        }`
      );
    }
    console.log(
      `  30-day burn: ${walletData.burn_30d.queries} queries · $${(walletData.burn_30d.cost_cents / 100).toFixed(2)} · ~$${walletData.burn_30d.avg_cost_per_query_cents.toFixed(4)}/query`
    );
    if (walletData.projected_days_to_empty !== null) {
      console.log(`  Runway: ~${walletData.projected_days_to_empty} days at current burn rate`);
    }
    if (walletData.tier === 'trial') {
      console.log(`  ${dim('Trial: $5.00 credit / 1,000 queries / 50 MB / 14 days')}`);
    }
    console.log();
    info('Commands: hebrah wallet --auto-reload on · hebrah topup --amount 20');
    return 0;
  } catch (err) {
    if (err instanceof ApiError) {
      error(err.message);
      if (err.suggestion) info(err.suggestion);
      return 4;
    }
    error((err as Error).message);
    return 4;
  }
}