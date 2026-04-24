"""
Database dependencies.
"""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from ..db.session import async_session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Database session dependency."""
    async with async_session_factory() as session:
        yield session