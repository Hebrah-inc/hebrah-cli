import { describe, expect, it, vi, beforeEach } from 'vitest';
import * as net from 'node:net';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import dbCommand from '../src/commands/db.js';
import { api } from '../src/api/client.js';
import { startPgWireProxy } from '../src/util/pgProxy.js';

describe('hebrah db command suite & PostgreSQL wire-protocol proxy', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.restoreAllMocks();
    process.env.HEBRAH_CREDENTIALS_DIR = '/tmp/hebrah-cli-empty-db-test';
    delete process.env.HEBRAH_ENV_ID;
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  it('displays help when invoked with no subcommand or --help', async () => {
    const code = await dbCommand([], { _argv: [] });
    expect(code).toBe(0);
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining('hebrah db — Database tunnel, local PostgreSQL proxy')
    );
  });

  it('outputs local proxy coordinates for `hebrah db proxy <env_id> 5432`', async () => {
    const code = await dbCommand(
      ['proxy', 'e858732a-828d-418b-ab48-4189d8a5cc04', '15433', '--json'],
      { _argv: ['proxy', 'e858732a-828d-418b-ab48-4189d8a5cc04', '15433', '--json'] }
    );
    expect(code).toBe(0);
    const output = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(output).toContain('e858732a-828d-418b-ab48-4189d8a5cc04');
    expect(output).toContain('127.0.0.1');
    expect(output).toContain('15433');
  });

  it('exports valid WireGuard configuration with 0600 permissions on --out', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hb-wg-test-'));
    const outFile = path.join(tmpDir, 'hb-env-e858732a.conf');

    const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce({
      environment_id: 'e858732a-828d-418b-ab48-4189d8a5cc04',
      filename: 'hb-env-e858732a.conf',
      client_ip: '10.42.0.5',
      server_endpoint: '127.0.0.1:51820',
      config_text:
        '[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.42.0.5/32\n\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 10.42.0.0/24\n'
    });

    const code = await dbCommand(
      ['wireguard', 'e858732a-828d-418b-ab48-4189d8a5cc04', '--out', outFile],
      {
        _argv: [
          'wireguard',
          'e858732a-828d-418b-ab48-4189d8a5cc04',
          '--out',
          outFile
        ]
      }
    );

    expect(code).toBe(0);
    expect(getSpy).toHaveBeenCalledWith(
      '/v1/environments/e858732a-828d-418b-ab48-4189d8a5cc04/wireguard/config',
      expect.objectContaining({ download: 'true' })
    );
    expect(fs.existsSync(outFile)).toBe(true);
    const written = fs.readFileSync(outFile, 'utf8');
    expect(written).toContain('Endpoint = 127.0.0.1:51820');
    const mode = fs.statSync(outFile).mode & 0o777;
    expect(mode).toBe(0o600);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('executes SQL queries via `hebrah db query`', async () => {
    const postSpy = vi.spyOn(api, 'post').mockResolvedValueOnce({
      environment_id: 'e858732a-828d-418b-ab48-4189d8a5cc04',
      addon: 'postgres',
      rows: [{ id: 'pat-1', mrn: 'MRN-1001', last_name: 'Rivera' }],
      row_count: 1,
      bytes_egressed: 128,
      duration_ms: 4
    });

    const code = await dbCommand(
      [
        'query',
        'e858732a-828d-418b-ab48-4189d8a5cc04',
        'SELECT id, mrn, last_name FROM patients LIMIT 1'
      ],
      {
        _argv: [
          'query',
          'e858732a-828d-418b-ab48-4189d8a5cc04',
          'SELECT id, mrn, last_name FROM patients LIMIT 1'
        ]
      }
    );
    expect(code).toBe(0);
    expect(postSpy).toHaveBeenCalledWith(
      '/v1/environments/e858732a-828d-418b-ab48-4189d8a5cc04/db/query',
      {
        sql: 'SELECT id, mrn, last_name FROM patients LIMIT 1',
        addon: 'postgres',
        actor_type: 'agent'
      }
    );
  });

  it('lists tables via `hebrah db tables`', async () => {
    const getSpy = vi.spyOn(api, 'get').mockResolvedValueOnce({
      environment_id: 'e858732a-828d-418b-ab48-4189d8a5cc04',
      tables: [
        {
          name: 'patients',
          schema: 'env_e858732a',
          row_count: 25,
          description: 'Synthetic patients'
        }
      ]
    });

    const code = await dbCommand(
      ['tables', 'e858732a-828d-418b-ab48-4189d8a5cc04'],
      { _argv: ['tables', 'e858732a-828d-418b-ab48-4189d8a5cc04'] }
    );
    expect(code).toBe(0);
    expect(getSpy).toHaveBeenCalledWith(
      '/v1/environments/e858732a-828d-418b-ab48-4189d8a5cc04/db/tables'
    );
  });

  it('starts a live PostgreSQL v3 wire-protocol TCP server and answers SQL queries', async () => {
    vi.spyOn(api, 'post').mockResolvedValue({
      columns: ['id', 'mrn'],
      rows: [{ id: 'pat-001', mrn: 'MRN-9001' }],
      row_count: 1
    });

    const proxy = await startPgWireProxy({
      envId: 'e858732a-828d-418b-ab48-4189d8a5cc04',
      port: 0, // kernel-assigned ephemeral port
      client: api
    });

    try {
      const responseText = await new Promise<string>((resolve, reject) => {
        const clientSocket = net.createConnection(
          { host: proxy.host, port: proxy.port },
          () => {
            // Send PG v3.0 StartupMessage (length 8, version 196608 = 0x00030000)
            const startup = Buffer.alloc(8);
            startup.writeInt32BE(8, 0);
            startup.writeInt32BE(196608, 4);
            clientSocket.write(startup);
          }
        );

        let sentQuery = false;
        let collected = Buffer.alloc(0);

        clientSocket.on('data', (chunk: Buffer) => {
          collected = Buffer.concat([collected, chunk]);
          const ascii = collected.toString('utf8');

          if (!sentQuery && collected.includes(Buffer.from('Z', 'ascii'))) {
            sentQuery = true;
            collected = Buffer.alloc(0);
            // Send Simple Query ('Q') packet
            const sqlBytes = Buffer.from(
              'SELECT id, mrn FROM public.patients LIMIT 1\0',
              'utf8'
            );
            const qPacket = Buffer.alloc(1 + 4 + sqlBytes.length);
            qPacket.write('Q', 0, 1, 'ascii');
            qPacket.writeInt32BE(4 + sqlBytes.length, 1);
            sqlBytes.copy(qPacket, 5);
            clientSocket.write(qPacket);
            return;
          }

          if (sentQuery && ascii.includes('SELECT 1')) {
            clientSocket.end();
            resolve(ascii);
          }
        });

        clientSocket.on('error', reject);
      });

      expect(responseText).toContain('MRN-9001');
      expect(responseText).toContain('SELECT 1');
    } finally {
      await proxy.close();
    }
  });
});
