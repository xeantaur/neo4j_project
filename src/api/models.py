"""
Pydantic response models and schemas for the FastAPI backend API.
"""

from typing import Generic, List, Optional, TypeVar, Literal, Dict
from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


# --- System Health & Readiness Schemas ---

class HealthResponse(BaseModel):
    """Liveness health check response model."""
    status: str = Field(default="ok", description="Application liveness status")
    app: str = Field(default="Network Traffic Analysis", description="Application name")


class ReadyResponse(BaseModel):
    """Database readiness check response model."""
    status: str = Field(default="ready", description="Database readiness status")
    database: str = Field(default="connected", description="Database connection status")


# --- Network & Topology Schemas ---

class IPAddressResponse(BaseModel):
    """Observed IP address model."""
    address: str = Field(description="Canonical IP address string")


class IPDetailResponse(BaseModel):
    """Detailed local graph context and flow counts for an IP address."""
    address: str = Field(description="Canonical IP address string")
    layer2_identifiers: List[str] = Field(description="Observed associated Layer 2 identifiers")
    outbound_flows: int = Field(description="Count of outgoing Layer 3 communications")
    inbound_flows: int = Field(description="Count of incoming Layer 3 communications")
    alerts_originated: int = Field(description="Count of security alerts where this IP was source")
    alerts_targeted: int = Field(description="Count of security alerts targeting this IP")
    traffic_metrics_mode: Literal["none", "basic", "enriched", "mixed"] = Field(
        default="none",
        description="Measurement availability mode for traffic communications incident to this IP",
    )
    distinct_outbound_peers: int = Field(
        default=0,
        description="Count of distinct destination IP peers contacted by this IP (fan-out)",
    )
    distinct_inbound_peers: int = Field(
        default=0,
        description="Count of distinct source IP peers contacting this IP (fan-in)",
    )
    distinct_destination_ports: int = Field(
        default=0,
        description="Count of distinct destination transport ports contacted by this IP",
    )
    observed_packets_sent: Optional[int] = Field(
        default=None,
        description="Total packets observed sent from this IP across enriched communications",
    )
    observed_packets_received: Optional[int] = Field(
        default=None,
        description="Total packets observed received by this IP across enriched communications",
    )
    observed_bytes_sent: Optional[int] = Field(
        default=None,
        description="Total bytes observed sent from this IP across enriched communications",
    )
    observed_bytes_received: Optional[int] = Field(
        default=None,
        description="Total bytes observed received by this IP across enriched communications",
    )
    first_observed: Optional[float] = Field(
        default=None,
        description="Earliest observation timestamp (seconds since epoch) across enriched incident communications",
    )
    last_observed: Optional[float] = Field(
        default=None,
        description="Latest observation timestamp (seconds since epoch) across enriched incident communications",
    )


class PeerResponse(BaseModel):
    """Communicating peer model."""
    peer_address: str = Field(description="Canonical IP address of peer")
    direction: Literal["outbound", "inbound"] = Field(description="Traffic direction relative to queried IP")
    protocols: List[str] = Field(description="Distinct observed protocols sorted alphabetically")


class Layer2IdentifierResponse(BaseModel):
    """Layer 2 hardware or local identifier model."""
    identifier: str = Field(description="Layer 2 MAC address or resolved local identifier")


class CommunicationResponse(BaseModel):
    """Layer 3 directional communication flow model."""
    source_ip: str = Field(description="Source IP address")
    target_ip: str = Field(description="Destination IP address")
    protocol: str = Field(description="Observed protocol value")
    flow_key: Optional[str] = Field(default=None, description="Deterministic 64-character SHA-256 flow identity key")
    src_port: Optional[int] = Field(default=None, description="Observed source transport port number")
    dst_port: Optional[int] = Field(default=None, description="Observed destination transport port number")
    observed_packet_count: Optional[int] = Field(default=None, description="Count of packets observed for this communication aggregate")
    observed_bytes: Optional[int] = Field(default=None, description="Total byte volume observed for this communication aggregate")
    first_seen: Optional[float] = Field(default=None, description="Earliest frame timestamp (seconds since epoch)")
    last_seen: Optional[float] = Field(default=None, description="Latest frame timestamp (seconds since epoch)")
    observed_window_seconds: Optional[float] = Field(default=None, description="Duration in seconds between first and last observed frames")


# --- Traffic Analytics Schemas (Phase 7C) ---

class ProtocolDistributionItem(BaseModel):
    """Aggregated metrics for an observed network protocol."""
    protocol: str = Field(description="Normalized protocol identifier")
    communication_aggregate_count: int = Field(description="Number of communication relationships using this protocol")
    observed_packet_count: Optional[int] = Field(default=None, description="Total observed packets (null if no enriched metrics)")
    observed_bytes: Optional[int] = Field(default=None, description="Total observed bytes (null if no enriched metrics)")


class DestinationPortDistributionItem(BaseModel):
    """Aggregated metrics for a destination transport port."""
    dst_port: int = Field(description="Destination port number")
    communication_aggregate_count: int = Field(description="Number of communication relationships targeting this port")
    observed_packet_count: Optional[int] = Field(default=None, description="Total observed packets (null if no enriched metrics)")
    observed_bytes: Optional[int] = Field(default=None, description="Total observed bytes (null if no enriched metrics)")


class FanOutItem(BaseModel):
    """Ranked fan-out metric for a source IP address."""
    address: str = Field(description="Source IP address")
    distinct_destination_ips: int = Field(description="Count of distinct destination IPs contacted")


class FanInItem(BaseModel):
    """Ranked fan-in metric for a destination IP address."""
    address: str = Field(description="Destination IP address")
    distinct_source_ips: int = Field(description="Count of distinct source IPs contacting this address")


class TrafficAnalyticsSummaryResponse(BaseModel):
    """Global traffic analytics summary and factual distribution metrics."""
    traffic_metrics_mode: Literal["none", "basic", "enriched", "mixed"] = Field(
        description="Factual classification of metric completeness across all persisted traffic aggregates",
    )
    total_communication_aggregates: int = Field(
        description="Total count of COMMUNICATED_TO relationships in graph",
    )
    enriched_communication_aggregates: int = Field(
        description="Count of COMMUNICATED_TO relationships containing complete Phase 7 metric attributes",
    )
    basic_communication_aggregates: int = Field(
        description="Count of legacy/basic COMMUNICATED_TO relationships lacking measurement attributes",
    )
    total_observed_packets: Optional[int] = Field(
        default=None,
        description="Sum of observed packets across enriched aggregates (null if no enriched metrics present)",
    )
    total_observed_bytes: Optional[int] = Field(
        default=None,
        description="Sum of observed bytes across enriched aggregates (null if no enriched metrics present)",
    )
    first_observed: Optional[float] = Field(
        default=None,
        description="Earliest frame timestamp across enriched aggregates (null if no enriched metrics present)",
    )
    last_observed: Optional[float] = Field(
        default=None,
        description="Latest frame timestamp across enriched aggregates (null if no enriched metrics present)",
    )
    protocol_distribution: List[ProtocolDistributionItem] = Field(
        default_factory=list,
        description="Distribution of communications across observed dissector protocols",
    )
    destination_port_distribution: List[DestinationPortDistributionItem] = Field(
        default_factory=list,
        description="Top destination transport ports by communication aggregate count",
    )
    top_fan_out: List[FanOutItem] = Field(
        default_factory=list,
        description="Top source IP addresses ranked by distinct destination IP count",
    )
    top_fan_in: List[FanInItem] = Field(
        default_factory=list,
        description="Top destination IP addresses ranked by distinct source IP count",
    )


class EndpointAnalyticsResponse(BaseModel):
    """Factual traffic and topology metrics for an observed IP endpoint."""
    address: str = Field(description="Canonical IP address")
    outbound_communication_aggregates: int = Field(description="Count of outgoing COMMUNICATED_TO relationships")
    inbound_communication_aggregates: int = Field(description="Count of incoming COMMUNICATED_TO relationships")
    distinct_outbound_peers: int = Field(description="Distinct destination IP addresses contacted (fan-out)")
    distinct_inbound_peers: int = Field(description="Distinct source IP addresses contacting this IP (fan-in)")
    distinct_destination_ports: int = Field(description="Distinct destination transport ports contacted")
    observed_packets_sent: Optional[int] = Field(default=None, description="Observed packets sent across enriched flows")
    observed_packets_received: Optional[int] = Field(default=None, description="Observed packets received across enriched flows")
    observed_bytes_sent: Optional[int] = Field(default=None, description="Observed bytes sent across enriched flows")
    observed_bytes_received: Optional[int] = Field(default=None, description="Observed bytes received across enriched flows")
    first_observed: Optional[float] = Field(default=None, description="Earliest observation timestamp on enriched incident flows")
    last_observed: Optional[float] = Field(default=None, description="Latest observation timestamp on enriched incident flows")
    traffic_metrics_mode: Literal["none", "basic", "enriched", "mixed"] = Field(
        description="Measurement availability mode for communications incident to this endpoint",
    )


# --- Security Alerts & Correlation Schemas ---

class AlertFactResponse(BaseModel):
    """Normalized security alert fact model."""
    fact_key: str = Field(description="Deterministic SHA-256 identity key")
    source_ip: str = Field(description="Source IP address recorded by the alert")
    target_ip: str = Field(description="Target/destination IP address recorded by the alert")
    sid: Optional[int] = Field(default=None, description="Snort / IDS signature ID")
    gid: Optional[int] = Field(default=None, description="Generator ID")
    rev: Optional[int] = Field(default=None, description="Rule revision")
    message: Optional[str] = Field(default=None, description="Alert message or rule description")
    priority: Optional[int] = Field(default=None, description="Alert severity priority")
    protocol: Optional[str] = Field(default=None, description="Observed alert protocol")
    src_port: Optional[int] = Field(default=None, description="Source port number")
    dst_port: Optional[int] = Field(default=None, description="Destination port number")


class TrafficAlertCorrelationResponse(BaseModel):
    """Correlated traffic communication flow with matching security alert fact."""
    source_ip: str = Field(description="Source IP address")
    target_ip: str = Field(description="Target IP address")
    traffic_protocol: str = Field(description="Observed traffic communication protocol")
    traffic_flow_key: Optional[str] = Field(default=None, description="Deterministic flow identity key of matching communication")
    traffic_src_port: Optional[int] = Field(default=None, description="Source port of matching communication")
    traffic_dst_port: Optional[int] = Field(default=None, description="Destination port of matching communication")
    fact_key: str = Field(description="Deterministic SHA-256 alert fact key")
    sid: Optional[int] = Field(default=None, description="Snort signature ID")
    message: Optional[str] = Field(default=None, description="Alert message description")
    priority: Optional[int] = Field(default=None, description="Alert severity priority")
    alert_protocol: Optional[str] = Field(default=None, description="Alert record protocol")


# --- Graph Traversal & Topology Schemas ---

class GraphNodeResponse(BaseModel):
    """Graph node response model with application-level identifiers."""
    id: str = Field(description="Application-level node identifier (e.g., 'ip:10.0.0.1')")
    type: Literal["IPAddress", "Layer2Identifier"] = Field(description="Graph node entity type")
    value: str = Field(description="Domain value (address or identifier)")


class GraphEdgeResponse(BaseModel):
    """Graph edge response model connecting application-level node IDs."""
    source: str = Field(description="Source node ID")
    target: str = Field(description="Target node ID")
    type: Literal["COMMUNICATED_TO", "OBSERVED_WITH"] = Field(description="Graph relationship type")
    protocol: Optional[str] = Field(default=None, description="Observed protocol on relationship")
    flow_key: Optional[str] = Field(default=None, description="Deterministic flow identity key for COMMUNICATED_TO")
    src_port: Optional[int] = Field(default=None, description="Source port number")
    dst_port: Optional[int] = Field(default=None, description="Destination port number")
    observed_packet_count: Optional[int] = Field(default=None, description="Count of observed packets")
    observed_bytes: Optional[int] = Field(default=None, description="Total observed byte volume")
    first_seen: Optional[float] = Field(default=None, description="Earliest frame timestamp")
    last_seen: Optional[float] = Field(default=None, description="Latest frame timestamp")
    observed_window_seconds: Optional[float] = Field(default=None, description="Observed duration in seconds")


class GraphNeighborhoodResponse(BaseModel):
    """Bounded local graph neighborhood response model."""
    center: str = Field(description="Canonical center IP address")
    depth: int = Field(description="Traversal depth (1 or 2)")
    nodes: List[GraphNodeResponse] = Field(description="Unique graph nodes in neighborhood")
    edges: List[GraphEdgeResponse] = Field(description="Relationships spanning the returned nodes")


class PathResponse(BaseModel):
    """Shortest communication path response model."""
    source: str = Field(description="Origin IP address")
    target: str = Field(description="Destination IP address")
    hops: List[str] = Field(description="Ordered sequence of IP addresses on path")
    protocols: List[str] = Field(description="Observed protocols along each hop")
    length: int = Field(description="Number of communication hops")


# --- Generic Pagination Envelope ---

class PaginatedResponse(BaseModel, Generic[T]):
    """Standard pagination envelope."""
    items: List[T] = Field(description="List of items for current page")
    total: int = Field(description="Total count of items matching the query filters")
    limit: int = Field(description="Maximum number of items requested")
    offset: int = Field(description="Offset of the first item in the collection")

    model_config = ConfigDict(arbitrary_types_allowed=True)


# --- Data Import & Workspace Replacement Schemas (Phase 6.5) ---

class ImportStatusResponse(BaseModel):
    """Data import enablement status and file size limit configuration."""
    enabled: bool = Field(description="Whether browser data import and workspace replacement are enabled")
    max_file_size_bytes: int = Field(description="Maximum allowable file size in bytes")
    max_file_size_mb: int = Field(description="Maximum allowable file size in megabytes")


class FileValidationResult(BaseModel):
    """Validation diagnostics and parsing summary for an individual uploaded file."""
    provided: bool = Field(description="Whether this file source was provided in the upload")
    filename: Optional[str] = Field(default=None, description="Original filename metadata")
    total_raw_records: Optional[int] = Field(default=None, description="Total raw input lines or items parsed")
    valid_records: Optional[int] = Field(default=None, description="Count of valid normalized domain records / communication aggregates")
    skipped_records: Optional[int] = Field(default=None, description="Count of skipped or malformed records")
    duplicate_records: Optional[int] = Field(default=None, description="Count of duplicate records identified")
    warning_counts: Dict[str, int] = Field(default_factory=dict, description="Categorized warning counts")
    sample_errors: List[str] = Field(default_factory=list, description="Bounded sample error descriptions")


class ImportValidationResponse(BaseModel):
    """Stateless validation response comparing uploaded data against ingestion rules."""
    valid: bool = Field(description="Overall validity of the provided upload dataset")
    can_import: bool = Field(description="Whether the dataset satisfies requirements for workspace replacement")
    traffic: FileValidationResult = Field(description="Validation results for network traffic dataset")
    alerts: FileValidationResult = Field(description="Validation results for security alerts dataset")
    message: str = Field(description="Summary message describing validation outcome")


class ImportCapabilities(BaseModel):
    """Available analysis capabilities derived from the imported source datasets."""
    network_topology: bool = Field(description="Whether network topology visualization is available")
    ip_investigation: bool = Field(description="Whether IP address context investigation is available")
    communication_paths: bool = Field(description="Whether path exploration analysis is applicable")
    alert_facts: bool = Field(description="Whether security alert facts are present")
    traffic_alert_correlations: bool = Field(description="Whether traffic/alert correlation analysis is applicable")


class ImportResultResponse(BaseModel):
    """Atomic workspace replacement result."""
    success: bool = Field(description="Whether the active workspace was successfully replaced")
    workspace_replaced: bool = Field(description="Confirmation that previous workspace data was cleared and replaced")
    traffic_records_persisted: int = Field(description="Count of normalized traffic records / communication aggregates persisted")
    alert_facts_persisted: int = Field(description="Count of AlertFact nodes persisted")
    capabilities: ImportCapabilities = Field(description="Active analysis capabilities in the new workspace")
    message: str = Field(description="Human-readable result summary")
