import { request } from './client';
import type {
  IPAddressResponse,
  IPDetailResponse,
  PeerResponse,
  Layer2IdentifierResponse,
  CommunicationResponse,
  TrafficAnalyticsSummaryResponse,
  EndpointAnalyticsResponse,
  PaginatedResponse,
} from './types';

// Traffic analytics (Phase 7C)
export function getTrafficAnalyticsSummary(
  signal?: AbortSignal
): Promise<TrafficAnalyticsSummaryResponse> {
  return request<TrafficAnalyticsSummaryResponse>('/api/v1/network/analytics/summary', { signal });
}

export type EndpointAnalyticsSortBy =
  | 'fan_out'
  | 'fan_in'
  | 'observed_bytes_sent'
  | 'observed_bytes_received'
  | 'observed_packets_sent'
  | 'observed_packets_received';

export function listEndpointAnalytics(
  sortBy: EndpointAnalyticsSortBy = 'fan_out',
  limit: number = 50,
  offset: number = 0,
  signal?: AbortSignal
): Promise<PaginatedResponse<EndpointAnalyticsResponse>> {
  return request<PaginatedResponse<EndpointAnalyticsResponse>>(
    '/api/v1/network/analytics/endpoints',
    { signal },
    { sort_by: sortBy, limit, offset }
  );
}

// Topology & context endpoints
export function listIPs(
  limit: number = 50,
  offset: number = 0,
  signal?: AbortSignal
): Promise<PaginatedResponse<IPAddressResponse>> {
  return request<PaginatedResponse<IPAddressResponse>>('/api/v1/network/ips', { signal }, { limit, offset });
}

export function getIPDetail(address: string, signal?: AbortSignal): Promise<IPDetailResponse> {
  return request<IPDetailResponse>(`/api/v1/network/ips/${encodeURIComponent(address)}`, { signal });
}

export function listIPPeers(
  address: string,
  direction: 'all' | 'outbound' | 'inbound' = 'all',
  limit: number = 50,
  offset: number = 0,
  signal?: AbortSignal
): Promise<PaginatedResponse<PeerResponse>> {
  return request<PaginatedResponse<PeerResponse>>(
    `/api/v1/network/ips/${encodeURIComponent(address)}/peers`,
    { signal },
    { direction, limit, offset }
  );
}

export function listIPLayer2(
  address: string,
  limit: number = 50,
  offset: number = 0,
  signal?: AbortSignal
): Promise<PaginatedResponse<Layer2IdentifierResponse>> {
  return request<PaginatedResponse<Layer2IdentifierResponse>>(
    `/api/v1/network/ips/${encodeURIComponent(address)}/layer2`,
    { signal },
    { limit, offset }
  );
}

export function listLayer2(
  limit: number = 50,
  offset: number = 0,
  signal?: AbortSignal
): Promise<PaginatedResponse<Layer2IdentifierResponse>> {
  return request<PaginatedResponse<Layer2IdentifierResponse>>('/api/v1/network/layer2', { signal }, { limit, offset });
}

export interface ListCommunicationsParams {
  source_ip?: string | null;
  target_ip?: string | null;
  protocol?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  sort_by?: 'identity' | 'observed_bytes' | 'observed_packets' | 'first_seen';
  limit?: number;
  offset?: number;
}

export function listCommunications(
  params?: ListCommunicationsParams,
  signal?: AbortSignal
): Promise<PaginatedResponse<CommunicationResponse>> {
  return request<PaginatedResponse<CommunicationResponse>>(
    '/api/v1/network/communications',
    { signal },
    {
      source_ip: params?.source_ip,
      target_ip: params?.target_ip,
      protocol: params?.protocol,
      src_port: params?.src_port,
      dst_port: params?.dst_port,
      sort_by: params?.sort_by,
      limit: params?.limit ?? 50,
      offset: params?.offset ?? 0,
    }
  );
}
