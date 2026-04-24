"""
Health check endpoint.
"""

import asyncio
import logging
from typing import Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as aioredis
from neo4j import AsyncGraphDatabase

from tbhm.api.deps import get_db
from tbhm.core.config import settings
from tbhm.core.tools import ToolVerifier

logger = logging.getLogger(__name__)

router = APIRouter()


async def check_postgres(db: AsyncSession) -> Dict[str, str]:
    """Check PostgreSQL connectivity."""
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "connected", "service": "postgresql"}
    except Exception as e:
        logger.error(f"PostgreSQL health check failed: {e}")
        return {"status": "disconnected", "service": "postgresql", "error": str(e)}


async def check_redis() -> Dict[str, str]:
    """Check Redis connectivity."""
    try:
        client = await aioredis.from_url(
            f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}",
            encoding="utf-8",
            decode_responses=True,
        )
        await client.ping()
        await client.close()
        return {"status": "connected", "service": "redis"}
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return {"status": "disconnected", "service": "redis", "error": str(e)}


async def check_neo4j() -> Dict[str, str]:
    """Check Neo4j connectivity."""
    try:
        driver = AsyncGraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
        )
        await driver.verify_connectivity()
        await driver.close()
        return {"status": "connected", "service": "neo4j"}
    except Exception as e:
        logger.error(f"Neo4j health check failed: {e}")
        return {"status": "disconnected", "service": "neo4j", "error": str(e)}


def check_tools() -> Dict[str, Dict]:
    """Check available CLI tools."""
    verifier = ToolVerifier()
    required = verifier.verify_required()
    optional = verifier.verify_optional()
    
    return {
        "required": {
            t.name: {
                "installed": t.installed,
                "version": t.version,
            }
            for t in required
        },
        "optional": {
            t.name: {
                "installed": t.installed,
                "version": t.version,
            }
            for t in optional
        },
        "ready": verifier.is_ready(),
    }


@router.get("/")
async def health_check(db: AsyncSession = Depends(get_db, use_cache=False)) -> Dict:
    """Health check endpoint with database connectivity."""
    postgres_status = await check_postgres(db)
    
    results = {
        "status": "healthy",
        "service": "TBHM API",
        "services": {
            "postgres": postgres_status,
        },
    }
    
    all_healthy = postgres_status.get("status") == "connected"
    
    return {
        "status": "healthy" if all_healthy else "degraded",
        "service": "TBHM API",
        "services": results["services"],
    }


@router.get("/ready")
async def readiness_check(db: AsyncSession = Depends(get_db, use_cache=False)) -> Dict:
    """Readiness check for all dependencies."""
    health_checks = [
        check_postgres(db),
        check_redis(),
        check_neo4j(),
    ]
    
    results = await asyncio.gather(*health_checks, return_exceptions=True)
    
    services = {}
    all_ready = True
    
    for result in results:
        if isinstance(result, Exception):
            all_ready = False
            continue
        services[result.get("service", "unknown")] = result
        if result.get("status") != "connected":
            all_ready = False
    
    tool_status = check_tools()
    services["tools"] = {
        "required": tool_status["required"],
        "optional": tool_status["optional"],
        "ready": tool_status["ready"],
    }
    
    return {
        "ready": all_ready,
        "services": services,
    }


@router.get("/tools")
async def tools_check() -> Dict:
    """Check available CLI tools."""
    return check_tools()