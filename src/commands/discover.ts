// `hebrah discover` — list available targets.
//
// Usage:
//   hebrah discover                       (all targets)
//   hebrah discover --pack audit          (filter by pack)
//   hebrah discover --pack audit fintech  (multiple packs)
//   hebrah discover --healthy             (only healthy targets)
//   hebrah discover --json                (machine-readable)

import { parseArgs } from 'node:util';
import { api } from '../api/client.js';
import { json, table, green, dim, error } from '../output/format.js';
import { getArgv } from '../util/args.js';

interface Target {
  target: string;
  connector: string;
  label: string;
  description: string;
  pack?: string;
  pack_id?: string;
  tables?: string[];
  tiers: string[];
  health: 'healthy' | 'degraded' | 'outage' | 'unknown';
  writes_allowed: boolean;
}

export default async function discover(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, _args);
  const { values } = parseArgs({
    args: argv,
    options: {
      pack: { type: 'string', multiple: true },
      healthy: { type: 'boolean', default: false },
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  const params: Record<string, string> = {};
  if (values.pack) {
    const packs = Array.isArray(values.pack) ? values.pack : [values.pack as string];
    params.pack = packs.join(',');
  }
  if (values.healthy) params.healthy = 'true';

  try {
    const targets = await api.get<Target[]>('/v1/connections/targets', params);

    if (values.json) {
      json(targets);
      return 0;
    }

    const rows = targets.map((t) => [
      t.target,
      t.connector,
      t.label,
      t.pack_id ?? t.pack ?? '(none)',
      healthBadge(t.health)
    ]);

    table(['TARGET', 'CONNECTOR', 'LABEL', 'PACK', 'HEALTH'], rows);

    console.log();
    console.log(dim(`Total: ${targets.length} target${targets.length === 1 ? '' : 's'}`));
    console.log(dim('Next: `hebrah inspect <target>` to see scope grammar.'));

    return 0;
  } catch (err) {
    error((err as Error).message);
    return 4;
  }
}

function healthBadge(h: Target['health']): string {
  switch (h) {
    case 'healthy': return green('healthy');
    case 'degraded': return 'degraded';
    case 'outage': return 'outage';
    case 'unknown': return dim('unknown');
  }
}