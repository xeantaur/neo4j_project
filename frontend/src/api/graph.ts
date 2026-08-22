import { request } from './client';
import type { GraphNeighborhoodResponse, PathResponse } from './types';

export function getNeighborhood(
  address: string,
  depth: 1 | 2 = 1,
  max_nodes: number = 50,
  signal?: AbortSignal
): Promise<GraphNeighborhoodResponse> {
  return request<GraphNeighborhoodResponse>(
    `/api/v1/graph/neighborhood/${encodeURIComponent(address)}`,
    { signal },
    { depth, max_nodes }
  );
}

export function getShortestPath(
  source: string,
  target: string,
  max_hops: number = 5,
  signal?: AbortSignal
): Promise<PathResponse> {
  return request<PathResponse>(
    '/api/v1/graph/path',
    { signal },
    { source, target, max_hops }
  );
}
