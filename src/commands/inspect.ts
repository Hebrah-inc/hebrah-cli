// `hebrah inspect <target>` — show scope grammar for a target.

import { api } from '../api/client.js';
import { json, kv, dim, bold } from '../output/format.js';

interface TargetDetail {
  target: string;
  connector: string;
  label: string;
  description: string;
  pack_id?: string;
  pack?: string;
  tables: string[];
  required_scopes: string[];
  tiers: string[];
  writes_allowed: boolean;
  example_scopes: string;
  sample_queries?: string[];
}

export default async function inspect(
  args: string[],
  options: Record<string, unknown>
): Promise<number> {
  const argv = (options._argv as string[] | undefined) ?? args;
  const target = argv.find((a) => !a.startsWith('-')) ?? args[0];
  if (!target) {
    console.error('hebrah inspect: target required');
    console.error('Usage: hebrah inspect <target>');
    return 1;
  }

  const flagOnly = argv.filter((a) => a !== target);
  const { values } = (await import('node:util')).parseArgs({
    args: flagOnly,
    options: {
      json: { type: 'boolean', default: false }
    },
    allowPositionals: false
  });

  try {
    const detail = await api.get<TargetDetail>(
      `/v1/connections/targets/${encodeURIComponent(target)}`
    );

    if (values.json) {
      json(detail);
      return 0;
    }

    console.log(bold(detail.label));
    console.log(dim(detail.description));
    console.log();

    kv([
      ['Target', detail.target],
      ['Connector', detail.connector],
      ['Pack', detail.pack_id ?? detail.pack ?? '(none)'],
      ['Tables', detail.tables.join(', ')],
      ['Tiers', detail.tiers.join(', ')],
      ['Writes', detail.writes_allowed ? 'allowed' : 'forbidden (read-only)']
    ]);

    console.log();
    console.log(bold('Required scopes:'));
    for (const scope of detail.required_scopes) {
      console.log(`  ${scope}`);
    }

    console.log();
    console.log(bold('Example:'));
    console.log(`  hebrah connect ${detail.target} --scopes ${detail.example_scopes}`);

    if (detail.sample_queries && detail.sample_queries.length > 0) {
      console.log();
      console.log(bold('Sample queries:'));
      for (const q of detail.sample_queries) {
        console.log(`  ${dim(q)}`);
      }
    }

    return 0;
  } catch (err) {
    console.error((err as Error).message);
    return 4;
  }
}