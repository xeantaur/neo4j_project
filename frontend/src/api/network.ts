import { request } from './client';
import type {
  IPAddressResponse,
  IPDetailResponse,
  PeerResponse,
  Layer2IdentifierResponse,
  CommunicationResponse,
  PaginatedResponse,
} from './types';

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
      limit: params?.limit ?? 50,
      offset: params?.offset ?? 0,
    }
  );
}
