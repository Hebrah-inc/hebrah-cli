// Hebrah API client — HTTP wrapper for api.hebrah.com.
//
// Wave 1: all endpoints hit the merged hebrah-api control plane.
// Auth: hb_conn_* key via Authorization: Bearer header.
//
// Usage:
//   import { api } from '../api/client.js';
//   const account = await api.post('/v1/agent/account', { orgName, inviteEmail });

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const DEFAULT_API_URL = process.env.HEBRAH_API_URL ?? 'https://api.hebrah.com';

interface ApiResponse<T> {
  status: number;
  data: T;
  headers: Record<string, string>;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly body: unknown,
    public readonly suggestion?: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

class HebrahApi {
  private baseUrl: string;
  private apiKey: string | null;

  constructor() {
    this.baseUrl = DEFAULT_API_URL;
    this.apiKey = this.loadApiKey();
  }

  private loadApiKey(): string | null {
    if (process.env.HEBRAH_API_KEY) return process.env.HEBRAH_API_KEY;
    try {
      const credPath = join(homedir(), '.hebrah', 'credentials');
      const raw = readFileSync(credPath, 'utf-8');
      const creds = JSON.parse(raw);
      return creds.apiKey ?? null;
    } catch {
      return null;
    }
  }

  setApiKey(key: string): void {
    this.apiKey = key;
  }

  async get<T>(path: string, params?: Record<string, string>): Promise<T> {
    return this.request<T>('GET', path, undefined, params);
  }

  async post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  async delete<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    params?: Record<string, string>
  ): Promise<T> {
    const url = new URL(path, this.baseUrl);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        url.searchParams.set(k, v);
      }
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': `hebrah-cli/0.1.0 (Node ${process.version})`
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });

    const responseBody = await response.text();
    let parsed: unknown;
    try {
      parsed = responseBody ? JSON.parse(responseBody) : null;
    } catch {
      parsed = responseBody;
    }

    if (!response.ok) {
      throw mapError(response.status, parsed);
    }

    return parsed as T;
  }
}

function mapError(status: number, body: unknown): ApiError {
  const message =
    typeof body === 'object' && body !== null && 'message' in body
      ? String((body as any).message)
      : `HTTP ${status}`;

  const suggestion = (body as any)?.suggestion;

  switch (status) {
    case 401:
      return new ApiError('Authentication required', status, body, 'Run "hebrah login" or set HEBRAH_API_KEY env var.');
    case 402:
      return new ApiError('Quota exceeded', status, body, 'Add credit at hebrah.com/pricing.');
    case 403:
      return new ApiError('Forbidden', status, body, suggestion);
    case 404:
      return new ApiError('Not found', status, body, suggestion);
    case 409:
      return new ApiError('Conflict', status, body, suggestion);
    case 410:
      return new ApiError('Connection revoked', status, body, 'Open a new connection with "hebrah connect".');
    case 429:
      return new ApiError('Rate limited', status, body, 'Back off and retry.');
    case 500:
    case 502:
    case 503:
    case 504:
      return new ApiError('Server error', status, body, 'Try again; if persistent, run with --debug.');
    default:
      return new ApiError(message, status, body, suggestion);
  }
}

export const api = new HebrahApi();