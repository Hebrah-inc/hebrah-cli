// `hebrah audit` — show / verify / export audit events.
//
// Subcommands:
//   hebrah audit <conn>                       (show events)
//   hebrah audit verify <conn>                (verify hash chain)
//   hebrah audit export <conn>                 (export as JSON)

import { parseArgs } from 'node:util';
import { writeFileSync } from 'node:fs';
import { api } from '../api/client.js';
import { json, table, dim, green, red, yellow } from '../output/format.js';

interface AuditEvent {
  id: string;
  eventType: string;
  bytesEgressed: number;
  costCents: number;
  scopeSnapshot: Record<string, unknown>;
  prevHash: string | null;
  eventHash: string;
  createdAt: string;
}

interface VerifyResponse {
  verified: boolean;
  eventsChecked: number;
  genesisHash: string;
  brokenAt: string | null;
}

export default async function audit(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? args;
  // First non-flag token is subcommand (verify|export|help) or connId
  const tokens = argv.filter((a) => !a.startsWith('-'));
  const subcommand = tokens[0];
  const connId = tokens[1] ?? tokens[0];

  if (subcommand === 'verify') {
    return auditVerify(connId, options);
  }
  if (subcommand === 'export') {
    return auditExport(connId, options);
  }
  if (subcommand === 'help' || !subcommand) {
    console.log('Usage:');
    console.log('  hebrah audit <conn>                       Show audit events');
    console.log('  hebrah audit verify <conn>                Verify hash chain');
    console.log('  hebrah audit export <conn> > audit.json   Export as JSON');
    return 0;
  }

  // Default: show events
  return auditShow(connId, options);
}

async function auditShow(connId: string, options: Record<string, unknown>): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? [];
  const { values } = parseArgs({
    args: argv,
    options: {
      limit: { type: 'string', default: '50' },
      since: { type: 'string' },
      event: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  const params: Record<string, string> = {
    limit: values.limit as string
  };
  if (values.since) params.since = values.since as string;
  if (values.event) params.event_type = values.event as string;

  try {
    const events = await api.get<AuditEvent[]>(`/v1/connections/${connId}/audit`, params);

    if (values.json) {
      json(events);
      return 0;
    }

    const rows = events.map((e) => [
      e.id.substring(0, 8),
      e.eventType,
      String(e.bytesEgressed),
      `$${(e.costCents / 100).toFixed(4)}`,
      e.createdAt
    ]);

    table(['EVENT_ID', 'TYPE', 'BYTES', 'COST', 'CREATED'], rows);

    console.log();
    console.log(dim(`Total: ${events.length} event${events.length === 1 ? '' : 's'}`));
    console.log(dim(`Verify: hebrah audit verify ${connId}`));

    return 0;
  } catch (err) {
    console.error((err as Error).message);
    return 4;
  }
}

async function auditVerify(connId: string, _options: Record<string, unknown>): Promise<number> {
  try {
    const result = await api.get<VerifyResponse>(`/v1/audit/verify?connection_id=${connId}`);

    if (result.verified) {
      console.log(green(`✓ Hash chain verified: ${result.eventsChecked} events, genesis ${result.genesisHash.substring(0, 16)}...`));
    } else {
      console.log(red(`✗ Hash chain BROKEN at event ${result.brokenAt}`));
      console.log(yellow(`  Events checked: ${result.eventsChecked}`));
      console.log(yellow(`  Genesis: ${result.genesisHash}`));
      return 1;
    }
    return 0;
  } catch (err) {
    console.error((err as Error).message);
    return 4;
  }
}

async function auditExport(connId: string, _options: Record<string, unknown>): Promise<number> {
  try {
    const events = await api.get<AuditEvent[]>(`/v1/connections/${connId}/audit?limit=10000`);

    const exported = {
      connectionId: connId,
      exportedAt: new Date().toISOString(),
      eventCount: events.length,
      genesisHash: events[0]?.prevHash ?? null,
      events
    };

    process.stdout.write(JSON.stringify(exported, null, 2) + '\n');

    return 0;
  } catch (err) {
    console.error((err as Error).message);
    return 4;
  }
}