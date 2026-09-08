// `hebrah topup` — add credit to your account via Stripe Checkout.
//
// Usage:
//   hebrah topup                                (interactive: prompt for amount)
//   hebrah topup --amount 20                    (USD; opens Stripe Checkout in browser)
//   hebrah topup --amount 20 --print            (print URL instead of opening browser)
//   hebrah topup --amount 20 --yes              (skip confirmation prompt)
//   hebrah topup --credits 5000                 (top up by query credits, not USD)
//   hebrah topup --portal                       (open Stripe Customer Portal for subs)
//
// Pricing per skill.md:
//   - $0.005 per query (after Personal tier metered)
//   - $0.08 per GB egress
//   - Trial: $1 free credit, 100 queries, 1 GB egress, 7-day TTL
//
// Implementation notes:
//   - Calls `POST /v1/billing/checkout-session` to mint a Stripe Checkout URL.
//   - Opens URL via `open` (macOS), `xdg-open` (Linux), or `cmd.exe /c start` (Windows).
//   - Falls back to printing the URL if no browser handler is available.
//   - The actual credit application happens via Stripe webhook → backend,
//     NOT through this command. User runs `hebrah usage` after paying to see balance.

import { parseArgs } from 'node:util';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output, platform } from 'node:process';
import { api, ApiError, TimeoutError } from '../api/client.js';
import { loadCredentials } from '../config/credentials.js';
import { json, success, info, warn, error, bold, dim } from '../output/format.js';

interface CheckoutSessionResponse {
  checkoutUrl: string;
  sessionId: string;
  amountCents: number;
  currency: string;
  expiresAt: string;
}

interface PortalSessionResponse {
  portalUrl: string;
  returnUrl: string;
}

interface AmountPreset {
  queries: number;
  egressGb: number;
  label: string;
  usdCents: number;
}

const AMOUNT_PRESETS: AmountPreset[] = [
  { queries: 1_000, egressGb: 1, label: '$5 — 1k queries + 1 GB egress', usdCents: 500 },
  { queries: 5_000, egressGb: 5, label: '$20 — 5k queries + 5 GB egress', usdCents: 2_000 },
  { queries: 20_000, egressGb: 20, label: '$80 — 20k queries + 20 GB egress', usdCents: 8_000 },
  { queries: 100_000, egressGb: 100, label: '$400 — 100k queries + 100 GB egress', usdCents: 40_000 }
];

export default async function topup(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? _args;
  const { values } = parseArgs({
    args: argv,
    options: {
      amount: { type: 'string' },
      credits: { type: 'string' },
      portal: { type: 'boolean', default: false },
      print: { type: 'boolean', default: false },
      yes: { type: 'boolean', short: 'y', default: false },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  // Customer Portal path — manage subscription, invoices, payment methods
  if (values.portal) {
    return openPortal(values.print === true, options);
  }

  // Validate amount
  const amountUsd = values.amount !== undefined ? parseFloat(values.amount as string) : NaN;
  const creditsRaw = values.credits as string | undefined;
  if (Number.isNaN(amountUsd) && !creditsRaw) {
    return interactiveTopup(options);
  }

  if (creditsRaw && !Number.isNaN(amountUsd)) {
    error('Use either --amount (USD) or --credits (queries), not both.');
    return 1;
  }

  // Convert credits → USD using $0.005/query at the per-query tier.
  let amountCents: number;
  let description: string;
  if (creditsRaw) {
    const queries = parseInt(creditsRaw, 10);
    if (!Number.isFinite(queries) || queries <= 0) {
      error('--credits must be a positive integer.');
      return 1;
    }
    amountCents = Math.ceil(queries * 0.5); // 0.5 cents per query at $0.005/query
    description = `${queries.toLocaleString()} queries (~$${(amountCents / 100).toFixed(2)})`;
  } else {
    if (amountUsd < 1 || amountUsd > 10_000) {
      error('--amount must be between $1 and $10,000.');
      return 1;
    }
    amountCents = Math.round(amountUsd * 100);
    description = `$${amountUsd.toFixed(2)} credit`;
  }

  // Interactive confirmation unless --yes
  if (!values.yes && input.isTTY) {
    const rl = createInterface({ input, output });
    console.log();
    info(`${bold(description)} → Stripe Checkout`);
    info(dim('Card not stored locally; Stripe hosts the payment page.'));
    const answer = (await rl.question('Continue? [Y/n] ')).trim().toLowerCase();
    rl.close();
    if (answer && answer !== 'y' && answer !== 'yes') {
      info('Cancelled.');
      return 0;
    }
  }

  // Ensure logged in (topup requires authenticated org)
  const creds = loadCredentials();
  if (!creds && !process.env.HEBRAH_API_KEY) {
    error('Not logged in. Run `hebrah signup` or `hebrah login` first.');
    return 2;
  }

  try {
    const session = await api.post<CheckoutSessionResponse>('/v1/billing/checkout-session', {
      amountCents,
      currency: 'usd',
      description
    });

    if (options.json || values.json) {
      json(session);
      return 0;
    }

    console.log();
    success(`Checkout session created: ${dim(session.sessionId)}`);
    info(`Amount: ${bold(`$${(session.amountCents / 100).toFixed(2)} ${session.currency.toUpperCase()}`)}`);
    info(`URL expires: ${session.expiresAt}`);

    if (values.print) {
      info(dim('Open this URL in your browser to complete payment:'));
      console.log(session.checkoutUrl);
      console.log();
      info('After paying, run `hebrah usage` to verify your balance updated.');
      return 0;
    }

    const opened = await openBrowser(session.checkoutUrl);
    if (opened) {
      info(`Opened in your browser. Complete payment there.`);
    } else {
      warn('Could not auto-open a browser. Open this URL manually:');
      console.log(session.checkoutUrl);
    }
    console.log();
    info('After paying, run `hebrah usage` to verify your balance updated.');
    return 0;
  } catch (err) {
    if (err instanceof TimeoutError) {
      error(`Topup timed out: ${err.message}`);
      if (err.suggestion) info(err.suggestion);
      return 4;
    }
    if (err instanceof ApiError) {
      error(err.message);
      if (err.suggestion) info(err.suggestion);
      // 402 here is a special case: user is trying to top up BECAUSE they're out
      // of credit. Don't tell them to add credit — that's what they're doing.
      if (err.statusCode === 402) {
        info('(If this is a billing-blocked account, contact hello@hebrah.com to recover access.)');
      }
      return 4;
    }
    error((err as Error).message);
    return 4;
  }
}

async function interactiveTopup(options: Record<string, unknown>): Promise<number> {
  if (!input.isTTY) {
    error('Non-interactive mode requires --amount <USD> or --credits <N>.');
    return 1;
  }

  const rl = createInterface({ input, output });
  console.log();
  info(bold('Choose a topup amount:'));
  for (let i = 0; i < AMOUNT_PRESETS.length; i++) {
    console.log(`  ${dim(`${i + 1}.`)} ${AMOUNT_PRESETS[i].label}`);
  }
  console.log(`  ${dim('5.')} Custom amount`);

  const choice = (await rl.question(dim('Select [1-5]: '))).trim();
  rl.close();

  let preset: AmountPreset | null = null;
  const idx = parseInt(choice, 10);
  if (idx >= 1 && idx <= AMOUNT_PRESETS.length) {
    preset = AMOUNT_PRESETS[idx - 1];
  } else if (idx === 5) {
    const rl2 = createInterface({ input, output });
    const raw = (await rl2.question('Amount in USD (min $1, max $10,000): ')).trim();
    rl2.close();
    const usd = parseFloat(raw);
    if (Number.isNaN(usd) || usd < 1 || usd > 10_000) {
      error('Invalid amount.');
      return 1;
    }
    preset = { queries: 0, egressGb: 0, label: `$${usd.toFixed(2)} credit`, usdCents: Math.round(usd * 100) };
  } else {
    error('Invalid selection.');
    return 1;
  }

  // Re-enter with --amount flag so the rest of the logic reuses the same path
  const fakeArgv = ['--amount', (preset.usdCents / 100).toFixed(2), '--yes'];
  return topup(fakeArgv, { ...options, _argv: fakeArgv });
}

async function openPortal(printOnly: boolean, _options: Record<string, unknown>): Promise<number> {
  const creds = loadCredentials();
  if (!creds && !process.env.HEBRAH_API_KEY) {
    error('Not logged in. Run `hebrah signup` or `hebrah login` first.');
    return 2;
  }

  try {
    const portal = await api.post<PortalSessionResponse>('/v1/billing/portal', {
      returnUrl: 'https://hebrah.com/pricing'
    });

    if (printOnly) {
      console.log(portal.portalUrl);
      return 0;
    }

    const opened = await openBrowser(portal.portalUrl);
    if (opened) {
      success('Opened Stripe Customer Portal in your browser.');
      info('Manage subscription, invoices, and payment methods.');
    } else {
      warn('Could not auto-open a browser. Open this URL manually:');
      console.log(portal.portalUrl);
    }
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

async function openBrowser(url: string): Promise<boolean> {
  // Pick the platform-appropriate opener
  let cmd: string;
  let args: string[];
  if (platform === 'darwin') {
    cmd = 'open';
    args = [url];
  } else if (platform === 'win32') {
    cmd = 'cmd.exe';
    args = ['/c', 'start', '""', url];
  } else {
    cmd = 'xdg-open';
    args = [url];
  }

  return new Promise<boolean>((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { detached: true, stdio: 'ignore' });
    } catch {
      resolve(false);
      return;
    }
    child.on('error', () => resolve(false));
    child.on('spawn', () => {
      child.unref();
      // Give it 500ms to actually open; if it exits immediately, opener missing
      setTimeout(() => resolve(true), 500);
    });
    // If the opener exits cleanly within 500ms, it likely wasn't found
    child.on('exit', (code: number | null) => {
      if (code !== null && code !== 0) resolve(false);
    });
  });
}