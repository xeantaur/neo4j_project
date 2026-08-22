/**
 * TypeScript interfaces mirroring the FastAPI backend Pydantic models.
 *
 * IMPORTANT: Nullable backend fields are typed explicitly as `T | null`
 * to accurately reflect JSON serialization.
 */

// System health & readiness
export interface HealthResponse {
  status: string;
  app: string;
}

export interface ReadyResponse {
  status: string;
  database: string;
}

// Network & topology
export interface IPAddressResponse {
  address: string;
}

export interface IPDetailResponse {
  address: string;
  layer2_identifiers: string[];
  outbound_flows: number;
  inbound_flows: number;
  alerts_originated: number;
  alerts_targeted: number;
}

export interface PeerResponse {
  peer_address: string;
  direction: 'outbound' | 'inbound';
  protocols: string[];
}

export interface Layer2IdentifierResponse {
  identifier: string;
}

export interface CommunicationResponse {
  source_ip: string;
  target_ip: string;
  protocol: string;
}

// Security alerts & correlation
export interface AlertFactResponse {
  fact_key: string;
  source_ip: string;
  target_ip: string;
  sid: number | null;
  gid: number | null;
  rev: number | null;
  message: string | null;
  priority: number | null;
  protocol: string | null;
  src_port: number | null;
  dst_port: number | null;
}

export interface TrafficAlertCorrelationResponse {
  source_ip: string;
  target_ip: string;
  traffic_protocol: string;
  fact_key: string;
  sid: number | null;
  message: string | null;
  priority: number | null;
  alert_protocol: string | null;
}

// Graph traversal & topology
export interface GraphNodeResponse {
  id: string;
  type: 'IPAddress' | 'Layer2Identifier';
  value: string;
}

export interface GraphEdgeResponse {
  source: string;
  target: string;
  type: 'COMMUNICATED_TO' | 'OBSERVED_WITH';
  protocol: string | null;
}

export interface GraphNeighborhoodResponse {
  center: string;
  depth: number;
  nodes: GraphNodeResponse[];
  edges: GraphEdgeResponse[];
}

export interface PathResponse {
  source: string;
  target: string;
  hops: string[];
  protocols: string[];
  length: number;
}

// Generic pagination envelope
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}
