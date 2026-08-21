"""
Health and readiness check route handlers.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from src.api.models import HealthResponse, ReadyResponse
from src.api.dependencies import get_read_repository
from src.graph.read_repository import Neo4jReadRepository

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness check: returns 200 if the API process is running.
    
    Makes ZERO database or network calls.
    """
    return HealthResponse(status="ok", app="Network Traffic Analysis")


@router.get("/ready", response_model=ReadyResponse)
def ready(repo: Neo4jReadRepository = Depends(get_read_repository)):
    """Readiness check: verifies connectivity to the Neo4j database instance.
    
    Returns 200 when Neo4j is reachable and authenticated; returns 503 otherwise.
    """
    if repo.check_connectivity():
        return ReadyResponse(status="ready", database="connected")
    
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "unready", "detail": "Database service unavailable"},
    )
