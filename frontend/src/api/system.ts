import { request } from './client';
import type { HealthResponse, ReadyResponse } from './types';

export function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request<HealthResponse>('/health', { signal });
}

export function getReady(signal?: AbortSignal): Promise<ReadyResponse> {
  return request<ReadyResponse>('/ready', { signal });
}
