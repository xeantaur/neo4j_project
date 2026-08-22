import { request } from './client';
import type { AlertFactResponse, PaginatedResponse } from './types';

export interface ListAlertFactsParams {
  source_ip?: string | null;
  target_ip?: string | null;
  priority?: number | null;
  sid?: number | null;
  protocol?: string | null;
  limit?: number;
  offset?: number;
}

export function listAlertFacts(
  params?: ListAlertFactsParams,
  signal?: AbortSignal
): Promise<PaginatedResponse<AlertFactResponse>> {
  return request<PaginatedResponse<AlertFactResponse>>(
    '/api/v1/alerts',
    { signal },
    {
      source_ip: params?.source_ip,
      target_ip: params?.target_ip,
      priority: params?.priority,
      sid: params?.sid,
      protocol: params?.protocol,
      limit: params?.limit ?? 50,
      offset: params?.offset ?? 0,
    }
  );
}

export function getAlertFact(fact_key: string, signal?: AbortSignal): Promise<AlertFactResponse> {
  return request<AlertFactResponse>(`/api/v1/alerts/${encodeURIComponent(fact_key)}`, { signal });
}
