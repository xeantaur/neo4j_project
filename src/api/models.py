"""
Pydantic response models and schemas for the FastAPI backend API.
"""

from typing import Generic, List, Optional, TypeVar, Literal
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


# --- Security Alerts & Correlation Schemas ---

class AlertFactResponse(BaseModel):
    """Normalized security alert fact model."""
    fact_key: str = Field(description="Deterministic SHA-256 identity key")
    source_ip: str = Field(description="Attacker / Source IP address")
    target_ip: str = Field(description="Victim / Target IP address")
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
