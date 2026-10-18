// `hebrah packs` — list connector packs.

import { parseArgs } from 'node:util';
import { api } from '../api/client.js';
import { json, table, dim, error } from '../output/format.js';
import { getArgv } from '../util/args.js';

interface Pack {
  pack_id: string;
  label: string;
  description: string;
  connector_count: number;
  target_count: number;
  wave: number;
}

export default async function packs(
  _args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = getArgv(options, _args);
  const { values } = parseArgs({
    args: argv,
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  try {
    const packs = await api.get<Pack[]>('/v1/connections/packs');

    if (values.json) {
      json(packs);
      return 0;
    }

    const rows = packs.map((p) => [
      p.pack_id,
      p.label,
      String(p.connector_count),
      String(p.target_count),
      `Wave ${p.wave}`
    ]);

    table(['PACK_ID', 'LABEL', 'CONNECTORS', 'TARGETS', 'AVAILABLE'], rows);

    console.log();
    console.log(dim(`Total: ${packs.length} pack${packs.length === 1 ? '' : 's'}`));
    console.log(dim('Discover targets: hebrah discover --pack <pack_id>'));

    return 0;
  } catch (err) {
    error((err as Error).message);
    return 4;
  }
}