"""
Health check endpoint.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from tbhm.api.deps import get_db

router = APIRouter()


@router.get("/")
async def health_check(db: AsyncSession = Depends(get_db, use_cache=False)):
    """Health check endpoint with database connectivity."""
    db_status = "unknown"

    try:
        await db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "disconnected"

    return {
        "status": "healthy",
        "service": "TBHM API",
        "database": db_status,
    }