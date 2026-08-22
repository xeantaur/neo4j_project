import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { request, ApiError } from '../api/client';

describe('HTTP API Client', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('serializes query parameters correctly', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ data: 'ok' }),
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await request('/api/v1/test', undefined, {
      limit: 50,
      offset: 0,
      protocol: 'TCP',
      empty: null,
      undef: undefined,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const calledUrl = fetchMock.mock.calls[0][0];
    expect(calledUrl).toContain('/api/v1/test?limit=50&offset=0&protocol=TCP');
    expect(calledUrl).not.toContain('empty');
    expect(calledUrl).not.toContain('undef');
  });

  it('handles 404 error with string detail', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      json: () => Promise.resolve({ detail: "IP address '10.0.0.99' not found in graph" }),
    }) as unknown as typeof fetch;

    await expect(request('/api/v1/network/ips/10.0.0.99')).rejects.toThrow(ApiError);
    try {
      await request('/api/v1/network/ips/10.0.0.99');
    } catch (err) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.detail).toBe("IP address '10.0.0.99' not found in graph");
    }
  });

  it('handles 422 error with array of validation details', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      statusText: 'Unprocessable Entity',
      json: () =>
        Promise.resolve({
          detail: [
            { msg: 'Invalid IP address format', loc: ['query', 'source_ip'] },
            { msg: 'Limit must be <= 200', loc: ['query', 'limit'] },
          ],
        }),
    }) as unknown as typeof fetch;

    try {
      await request('/api/v1/network/communications');
      expect.unreachable('Should have thrown ApiError');
    } catch (err) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.detail).toContain('Invalid IP address format');
      expect(apiErr.detail).toContain('Limit must be <= 200');
    }
  });

  it('handles 503 service unavailable error without crashing', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
      statusText: 'Service Unavailable',
      json: () => Promise.resolve({ detail: 'Database unavailable' }),
    }) as unknown as typeof fetch;

    try {
      await request('/ready');
      expect.unreachable('Should have thrown ApiError');
    } catch (err) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(503);
      expect(apiErr.detail).toBe('Database unavailable');
    }
  });

  it('handles network failure gracefully', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Failed to fetch'));

    try {
      await request('/health');
      expect.unreachable('Should have thrown ApiError');
    } catch (err) {
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(0);
      expect(apiErr.message).toContain('Could not connect to server');
    }
  });
});
