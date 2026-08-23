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

// Traffic metrics mode
export type TrafficMetricsMode = 'none' | 'basic' | 'enriched' | 'mixed';

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
  traffic_metrics_mode: TrafficMetricsMode;
  distinct_outbound_peers: number;
  distinct_inbound_peers: number;
  distinct_destination_ports: number;
  observed_packets_sent: number | null;
  observed_packets_received: number | null;
  observed_bytes_sent: number | null;
  observed_bytes_received: number | null;
  first_observed: number | null;
  last_observed: number | null;
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
  flow_key: string | null;
  src_port: number | null;
  dst_port: number | null;
  observed_packet_count: number | null;
  observed_bytes: number | null;
  first_seen: number | null;
  last_seen: number | null;
  observed_window_seconds: number | null;
}

// Traffic analytics (Phase 7C)
export interface ProtocolDistributionItem {
  protocol: string;
  communication_aggregate_count: number;
  observed_packet_count: number | null;
  observed_bytes: number | null;
}

export interface DestinationPortDistributionItem {
  dst_port: number;
  communication_aggregate_count: number;
  observed_packet_count: number | null;
  observed_bytes: number | null;
}

export interface FanOutItem {
  address: string;
  distinct_destination_ips: number;
}

export interface FanInItem {
  address: string;
  distinct_source_ips: number;
}

export interface TrafficAnalyticsSummaryResponse {
  traffic_metrics_mode: TrafficMetricsMode;
  total_communication_aggregates: number;
  enriched_communication_aggregates: number;
  basic_communication_aggregates: number;
  total_observed_packets: number | null;
  total_observed_bytes: number | null;
  first_observed: number | null;
  last_observed: number | null;
  protocol_distribution: ProtocolDistributionItem[];
  destination_port_distribution: DestinationPortDistributionItem[];
  top_fan_out: FanOutItem[];
  top_fan_in: FanInItem[];
}

export interface EndpointAnalyticsResponse {
  address: string;
  outbound_communication_aggregates: number;
  inbound_communication_aggregates: number;
  distinct_outbound_peers: number;
  distinct_inbound_peers: number;
  distinct_destination_ports: number;
  observed_packets_sent: number | null;
  observed_packets_received: number | null;
  observed_bytes_sent: number | null;
  observed_bytes_received: number | null;
  first_observed: number | null;
  last_observed: number | null;
  traffic_metrics_mode: TrafficMetricsMode;
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
  traffic_flow_key: string | null;
  traffic_src_port: number | null;
  traffic_dst_port: number | null;
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
  flow_key: string | null;
  src_port: number | null;
  dst_port: number | null;
  observed_packet_count: number | null;
  observed_bytes: number | null;
  first_seen: number | null;
  last_seen: number | null;
  observed_window_seconds: number | null;
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

// Data import & workspace replacement (Phase 6.5)
export interface ImportStatusResponse {
  enabled: boolean;
  max_file_size_bytes: number;
  max_file_size_mb: number;
}

export interface FileValidationResult {
  provided: boolean;
  filename: string | null;
  total_raw_records: number | null;
  valid_records: number | null;
  skipped_records: number | null;
  duplicate_records: number | null;
  warning_counts: Record<string, number>;
  sample_errors: string[];
}

export interface ImportValidationResponse {
  valid: boolean;
  can_import: boolean;
  traffic: FileValidationResult;
  alerts: FileValidationResult;
  message: string;
}

export interface ImportCapabilities {
  network_topology: boolean;
  ip_investigation: boolean;
  communication_paths: boolean;
  alert_facts: boolean;
  traffic_alert_correlations: boolean;
}

export interface ImportResultResponse {
  success: boolean;
  workspace_replaced: boolean;
  traffic_records_persisted: number;
  alert_facts_persisted: number;
  capabilities: ImportCapabilities;
  message: string;
}
