/**
 * Base HTTP client wrapper using native fetch.
 */

export class ApiError extends Error {
  public status: number;
  public detail: string;

  constructor(status: number, detail: string, message?: string) {
    super(message || detail || `API Error: HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

export async function request<T>(
  path: string,
  options?: RequestInit,
  params?: Record<string, string | number | boolean | null | undefined>
): Promise<T> {
  let url = `${BASE_URL}${path}`;

  if (params) {
    const searchParams = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== '') {
        searchParams.append(key, String(value));
      }
    }
    const qs = searchParams.toString();
    if (qs) {
      url += `${url.includes('?') ? '&' : '?'}${qs}`;
    }
  }

  let response: Response;
  try {
    response = await fetch(url, {
      ...options,
      headers: {
        Accept: 'application/json',
        ...options?.headers,
      },
    });
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : 'Network failure';
    throw new ApiError(0, errorMsg, `Could not connect to server: ${errorMsg}`);
  }

  if (!response.ok) {
    let errorDetail = response.statusText || `HTTP ${response.status}`;
    try {
      const errorJson = await response.json();
      if (typeof errorJson?.detail === 'string') {
        errorDetail = errorJson.detail;
      } else if (Array.isArray(errorJson?.detail)) {
        // FastAPI 422 validation errors array
        errorDetail = errorJson.detail
          .map((d: { msg?: string; loc?: (string | number)[] }) => d.msg || 'Validation error')
          .join(', ');
      }
    } catch {
      // Non-JSON error response
    }
    throw new ApiError(response.status, errorDetail);
  }

  return response.json() as Promise<T>;
}
