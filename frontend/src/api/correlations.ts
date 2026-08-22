import { request } from './client';
import type { TrafficAlertCorrelationResponse, PaginatedResponse } from './types';

export function listTrafficAlertCorrelations(
  limit: number = 50,
  offset: number = 0,
  signal?: AbortSignal
): Promise<PaginatedResponse<TrafficAlertCorrelationResponse>> {
  return request<PaginatedResponse<TrafficAlertCorrelationResponse>>(
    '/api/v1/correlations/traffic-alerts',
    { signal },
    { limit, offset }
  );
}
