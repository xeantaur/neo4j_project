"""
FastAPI application factory and server configuration.
"""

import logging
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from neo4j.exceptions import ServiceUnavailable, AuthError

from src.config import get_cors_origins, APP_NAME
from src.api.dependencies import lifespan
from src.api.routes import health, network, alerts, correlations, graph, import_data

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title=f"{APP_NAME} — Graph Query API",
        version="1.1.0",
        description=(
            "Read-oriented graph analysis API with explicitly gated data-import "
            "mutation endpoints for exploring network traffic topology, Layer 2/3 associations, "
            "and normalized security alert facts in Neo4j."
        ),
        lifespan=lifespan,
    )

    # --- CORS Configuration ---
    # Default is disabled (empty list). Only add CORSMiddleware if explicitly configured.
    cors_origins = get_cors_origins()
    if cors_origins:
        logger.info("Enabling CORS for origins: %s", cors_origins)
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["*"],
        )

    # --- Global Exception Handlers for Database Errors ---
    @app.exception_handler(ConnectionError)
    def connection_error_handler(request: Request, exc: ConnectionError):
        logger.error("Database connection error on %s: %s", request.url.path, exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Database service unavailable"},
        )

    @app.exception_handler(ServiceUnavailable)
    def neo4j_unavailable_handler(request: Request, exc: ServiceUnavailable):
        logger.error("Neo4j ServiceUnavailable on %s: %s", request.url.path, exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Database service unavailable"},
        )

    @app.exception_handler(AuthError)
    def neo4j_auth_error_handler(request: Request, exc: AuthError):
        logger.error("Neo4j AuthError on %s: %s", request.url.path, exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Database authentication failure"},
        )

    @app.exception_handler(Exception)
    def generic_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled server exception on %s: %s", request.url.path, exc, exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )

    # --- Router Registration ---
    app.include_router(health.router)
    app.include_router(network.router)
    app.include_router(alerts.router)
    app.include_router(correlations.router)
    app.include_router(graph.router)
    app.include_router(import_data.router)

    return app


# Default app instance for Uvicorn
app = create_app()
