"""
FastAPI dependency injection and lifecycle management.
"""

import ipaddress
import logging
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Request, HTTPException
from neo4j import GraphDatabase, Driver

from src.config import get_optional_neo4j_config
from src.graph.read_repository import Neo4jReadRepository

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan: initialize and close shared Neo4j driver."""
    driver: Optional[Driver] = None
    cfg = get_optional_neo4j_config()

    if cfg is not None:
        try:
            logger.info("Initializing Neo4j driver for API at %s", cfg["uri"])
            driver = GraphDatabase.driver(cfg["uri"], auth=(cfg["username"], cfg["password"]))
        except Exception as exc:
            logger.warning("Could not initialize Neo4j driver during startup: %s", exc)
            driver = None
    else:
        logger.info("Neo4j configuration not fully provided; running without active database connection.")

    app.state.driver = driver
    yield

    if getattr(app.state, "driver", None) is not None:
        try:
            logger.info("Closing shared Neo4j driver...")
            app.state.driver.close()
        except Exception as exc:
            logger.warning("Error closing Neo4j driver on shutdown: %s", exc)


def get_read_repository(request: Request) -> Neo4jReadRepository:
    """Provide a Neo4jReadRepository initialized with the shared driver from app state."""
    driver = getattr(request.app.state, "driver", None)
    return Neo4jReadRepository(driver)


def validate_canonical_ip(ip_str: str) -> str:
    """Validate IPv4 or IPv6 address format and return its canonical string representation.
    
    Raises:
        HTTPException (422): If ip_str is not a valid IP address.
    """
    if not ip_str or not isinstance(ip_str, str):
        raise HTTPException(
            status_code=422,
            detail="IP address string must not be empty",
        )
    try:
        return str(ipaddress.ip_address(ip_str.strip()))
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid IP address format: '{ip_str}'",
        )
