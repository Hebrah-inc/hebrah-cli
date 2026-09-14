import { describe, expect, it } from 'vitest';
import { startLoopbackAuth } from '../src/util/loopback.js';

describe('startLoopbackAuth', () => {
  it('starts an ephemeral server and generates a 64-char hex state', async () => {
    const loopback = await startLoopbackAuth();
    try {
      expect(loopback.port).toBeGreaterThan(0);
      expect(loopback.state).toMatch(/^[a-f0-9]{64}$/);
    } finally {
      loopback.close();
    }
  });

  it('receives successful authorization callback and returns credentials', async () => {
    const loopback = await startLoopbackAuth();
    const waitPromise = loopback.waitForCallback(5000);

    const callbackUrl = `http://127.0.0.1:${loopback.port}/callback?state=${loopback.state}&apiKey=hb_conn_test1234567890abcdef&orgId=org-test-uuid&orgName=Test+Corp`;
    const res = await fetch(callbackUrl);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Authentication Successful');
    expect(html).toContain('Test Corp');

    const result = await waitPromise;
    expect(result).toEqual({
      apiKey: 'hb_conn_test1234567890abcdef',
      orgId: 'org-test-uuid',
      orgName: 'Test Corp'
    });
  });

  it('rejects callback with mismatched state (CSRF guard)', async () => {
    const loopback = await startLoopbackAuth();
    const waitPromise = loopback.waitForCallback(5000);

    const badCallbackUrl = `http://127.0.0.1:${loopback.port}/callback?state=wrong_state&apiKey=hb_conn_test1234567890abcdef&orgId=org-1`;
    const [res] = await Promise.all([
      fetch(badCallbackUrl),
      expect(waitPromise).rejects.toThrow('CSRF state verification failed')
    ]);
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain('CSRF verification failed');
  });

  it('rejects callback with access_denied error parameter', async () => {
    const loopback = await startLoopbackAuth();
    const waitPromise = loopback.waitForCallback(5000);

    const deniedUrl = `http://127.0.0.1:${loopback.port}/callback?error=access_denied&error_description=User+declined`;
    const [res] = await Promise.all([
      fetch(deniedUrl),
      expect(waitPromise).rejects.toThrow('Authorization failed: User declined')
    ]);
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain('Authorization Denied');
  });

  it('rejects callback with invalid API key prefix', async () => {
    const loopback = await startLoopbackAuth();
    const waitPromise = loopback.waitForCallback(5000);

    const invalidKeyUrl = `http://127.0.0.1:${loopback.port}/callback?state=${loopback.state}&apiKey=invalid_prefix_key&orgId=org-1`;
    const [res] = await Promise.all([
      fetch(invalidKeyUrl),
      expect(waitPromise).rejects.toThrow('Invalid or missing API key')
    ]);
    expect(res.status).toBe(400);
  });

  it('times out if no callback is received before deadline', async () => {
    const loopback = await startLoopbackAuth();
    await expect(loopback.waitForCallback(50)).rejects.toThrow('Login timed out');
  });
});
