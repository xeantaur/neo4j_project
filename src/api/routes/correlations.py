"""
Cross-domain correlation route handlers.
"""

from fastapi import APIRouter, Depends, Query

from src.api.models import TrafficAlertCorrelationResponse, PaginatedResponse
from src.api.dependencies import get_read_repository
from src.graph.read_repository import Neo4jReadRepository

router = APIRouter(prefix="/api/v1/correlations", tags=["Correlations"])


@router.get("/traffic-alerts", response_model=PaginatedResponse[TrafficAlertCorrelationResponse])
def list_traffic_alert_correlations(
    limit: int = Query(default=50, ge=1, le=200, description="Max items per page"),
    offset: int = Query(default=0, ge=0, description="Offset starting index"),
    repo: Neo4jReadRepository = Depends(get_read_repository),
) -> PaginatedResponse[TrafficAlertCorrelationResponse]:
    """Retrieve communicating IP pairs that also exhibit matching security alert facts."""
    items, total = repo.list_traffic_alert_correlations(limit=limit, offset=offset)
    return PaginatedResponse[TrafficAlertCorrelationResponse](
        items=[TrafficAlertCorrelationResponse(**item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )
