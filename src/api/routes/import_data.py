"""
Data import API routes for browser-driven workspace replacement.

Provides:
- GET /api/v1/import/status: Feature enablement status and file size limits
- POST /api/v1/import/validate: Stateless dataset validation without database modification
- POST /api/v1/import: Atomic workspace replacement with uploaded datasets
"""

import logging
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status
from neo4j.exceptions import ServiceUnavailable, AuthError

from src.config import get_data_import_config
from src.api.dependencies import get_write_repository
from src.graph.repository import Neo4jRepository
from src.services.import_service import (
    ImportService,
    FileTooLargeError,
    ImportConflictError,
    ImportValidationError,
)
from src.api.models import (
    ImportStatusResponse,
    ImportValidationResponse,
    ImportResultResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/import", tags=["Data Import"])


@router.get(
    "/status",
    response_model=ImportStatusResponse,
    summary="Get data import configuration and enablement status",
)
def get_import_status() -> ImportStatusResponse:
    """Return whether browser data import is enabled and configured file size limits.

    Always accessible regardless of DATA_IMPORT_ENABLED setting.
    """
    cfg = get_data_import_config()
    return ImportStatusResponse(
        enabled=cfg["enabled"],
        max_file_size_bytes=cfg["max_file_size_bytes"],
        max_file_size_mb=cfg["max_file_size_mb"],
    )


@router.post(
    "/validate",
    response_model=ImportValidationResponse,
    summary="Statelessly validate uploaded datasets without modifying Neo4j",
)
def validate_import_data(
    traffic_file: Optional[UploadFile] = File(None, description="Network traffic TSV export"),
    alerts_file: Optional[UploadFile] = File(None, description="IDS/Snort JSON alerts export"),
) -> ImportValidationResponse:
    """Validate uploaded traffic and/or alert files statelessly.

    Enforces DATA_IMPORT_ENABLED=true and per-file size limits.
    Never modifies the Neo4j database.
    """
    cfg = get_data_import_config()
    if not cfg["enabled"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Data import is disabled by server configuration.",
        )

    if traffic_file is None and alerts_file is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one file ('traffic_file' or 'alerts_file') must be provided.",
        )

    try:
        validation_res, _, _ = ImportService.validate_files(
            traffic_file=traffic_file,
            alerts_file=alerts_file,
            max_bytes=cfg["max_file_size_bytes"],
            max_mb=cfg["max_file_size_mb"],
        )
        return validation_res
    except FileTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(exc),
        )


@router.post(
    "",
    response_model=ImportResultResponse,
    summary="Atomically replace active analysis workspace with uploaded datasets",
)
def import_workspace_data(
    traffic_file: Optional[UploadFile] = File(None, description="Network traffic TSV export"),
    alerts_file: Optional[UploadFile] = File(None, description="IDS/Snort JSON alerts export"),
    repository: Neo4jRepository = Depends(get_write_repository),
) -> ImportResultResponse:
    """Independently validate and atomically replace active workspace data in Neo4j.

    Enforces:
    - DATA_IMPORT_ENABLED=true
    - Size limits per file
    - Independent validation check (refuses mutation if invalid)
    - Single-process concurrency lock (409 Conflict if busy)
    - Atomic Neo4j transaction rollback if persistence fails
    """
    cfg = get_data_import_config()
    if not cfg["enabled"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Data import is disabled by server configuration.",
        )

    if traffic_file is None and alerts_file is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one file ('traffic_file' or 'alerts_file') must be provided.",
        )

    try:
        return ImportService.execute_import(
            traffic_file=traffic_file,
            alerts_file=alerts_file,
            max_bytes=cfg["max_file_size_bytes"],
            max_mb=cfg["max_file_size_mb"],
            repository=repository,
        )
    except ImportConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    except FileTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(exc),
        )
    except ImportValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    except (ConnectionError, ServiceUnavailable):
        logger.error("Database connection unavailable during workspace replacement.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable",
        )
    except AuthError:
        logger.error("Database authentication failure during workspace replacement.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database authentication failure",
        )
