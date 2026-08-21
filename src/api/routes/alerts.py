"""
Security alert route handlers.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, Path, HTTPException, status

from src.api.models import AlertFactResponse, PaginatedResponse
from src.api.dependencies import get_read_repository, validate_canonical_ip
from src.graph.read_repository import Neo4jReadRepository

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


@router.get("", response_model=PaginatedResponse[AlertFactResponse])
def list_alert_facts(
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP address"),
    target_ip: Optional[str] = Query(default=None, description="Filter by destination IP address"),
    priority: Optional[int] = Query(default=None, ge=1, description="Filter by alert priority severity"),
    sid: Optional[int] = Query(default=None, ge=0, description="Filter by Snort / IDS signature ID"),
    protocol: Optional[str] = Query(default=None, description="Filter by alert protocol"),
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page"),
    offset: int = Query(default=0, ge=0, description="Offset starting index"),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> PaginatedResponse[AlertFactResponse]:
    """Retrieve a filterable, paginated list of normalized security alert facts."""
    can_src = validate_canonical_ip(source_ip) if source_ip else None
    can_dst = validate_canonical_ip(target_ip) if target_ip else None

    items, total = repo.list_alert_facts(
        source_ip=can_src,
        target_ip=can_dst,
        priority=priority,
        sid=sid,
        protocol=protocol,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse[AlertFactResponse](
        items=[AlertFactResponse(**item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{fact_key}", response_model=AlertFactResponse)
def get_alert_fact_by_key(
    fact_key: str = Path(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Deterministic 64-character lowercase SHA-256 fact key",
    ),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> AlertFactResponse:
    """Retrieve a single normalized security alert fact by its deterministic SHA-256 identity key."""
    record = repo.get_alert_fact(fact_key)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert fact with key '{fact_key}' not found",
        )
    return AlertFactResponse(**record)
