"""
Network and topology route handlers.
"""

from typing import Optional, Literal
from fastapi import APIRouter, Depends, Query, HTTPException, status

from src.api.models import (
    IPAddressResponse,
    IPDetailResponse,
    PeerResponse,
    Layer2IdentifierResponse,
    CommunicationResponse,
    PaginatedResponse,
)
from src.api.dependencies import get_read_repository, validate_canonical_ip
from src.graph.read_repository import Neo4jReadRepository

router = APIRouter(prefix="/api/v1/network", tags=["Network"])


@router.get("/ips", response_model=PaginatedResponse[IPAddressResponse])
def list_ip_addresses(
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page"),
    offset: int = Query(default=0, ge=0, description="Offset starting index"),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> PaginatedResponse[IPAddressResponse]:
    """Retrieve a paginated list of observed IP addresses."""
    items, total = repo.list_ips(limit=limit, offset=offset)
    return PaginatedResponse[IPAddressResponse](
        items=[IPAddressResponse(**item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/ips/{address}", response_model=IPDetailResponse)
def get_ip_address_detail(
    address: str,
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> IPDetailResponse:
    """Retrieve detailed local graph context, associated Layer 2 identifiers, and flow counts for an IP."""
    canonical_address = validate_canonical_ip(address)
    detail = repo.get_ip_detail(canonical_address)
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address '{canonical_address}' not found in graph",
        )
    return IPDetailResponse(**detail)


@router.get("/ips/{address}/peers", response_model=PaginatedResponse[PeerResponse])
def list_ip_peers(
    address: str,
    direction: Literal["outbound", "inbound", "all"] = Query(
        default="all",
        description="Direction of communication relative to queried IP",
    ),
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page"),
    offset: int = Query(default=0, ge=0, description="Offset starting index"),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> PaginatedResponse[PeerResponse]:
    """List communicating peers and observed protocols for an IP address."""
    canonical_address = validate_canonical_ip(address)
    result = repo.list_ip_peers(canonical_address, direction=direction, limit=limit, offset=offset)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address '{canonical_address}' not found in graph",
        )
    items, total = result
    return PaginatedResponse[PeerResponse](
        items=[PeerResponse(**item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/ips/{address}/layer2", response_model=PaginatedResponse[Layer2IdentifierResponse])
def list_ip_layer2_associations(
    address: str,
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page"),
    offset: int = Query(default=0, ge=0, description="Offset starting index"),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> PaginatedResponse[Layer2IdentifierResponse]:
    """Retrieve paginated Layer 2 identifiers observed in association with an IP address."""
    canonical_address = validate_canonical_ip(address)
    result = repo.list_ip_layer2(canonical_address, limit=limit, offset=offset)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address '{canonical_address}' not found in graph",
        )
    items, total = result
    return PaginatedResponse[Layer2IdentifierResponse](
        items=[Layer2IdentifierResponse(**item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/layer2", response_model=PaginatedResponse[Layer2IdentifierResponse])
def list_layer2_identifiers(
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page"),
    offset: int = Query(default=0, ge=0, description="Offset starting index"),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> PaginatedResponse[Layer2IdentifierResponse]:
    """Retrieve a paginated list of all observed Layer 2 hardware MAC or local identifiers."""
    items, total = repo.list_layer2_identifiers(limit=limit, offset=offset)
    return PaginatedResponse[Layer2IdentifierResponse](
        items=[Layer2IdentifierResponse(**item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/communications", response_model=PaginatedResponse[CommunicationResponse])
def list_communications(
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP address"),
    target_ip: Optional[str] = Query(default=None, description="Filter by destination IP address"),
    protocol: Optional[str] = Query(default=None, description="Filter by observed protocol (e.g., TCP, UDP, HTTP)"),
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page"),
    offset: int = Query(default=0, ge=0, description="Offset starting index"),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> PaginatedResponse[CommunicationResponse]:
    """Retrieve a filterable, paginated list of observed Layer 3 IP-to-IP communications."""
    can_src = validate_canonical_ip(source_ip) if source_ip else None
    can_dst = validate_canonical_ip(target_ip) if target_ip else None

    items, total = repo.list_communications(
        source_ip=can_src,
        target_ip=can_dst,
        protocol=protocol,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse[CommunicationResponse](
        items=[CommunicationResponse(**item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )
