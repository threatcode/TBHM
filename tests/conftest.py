"""Pytest configuration and fixtures."""

import asyncio
import uuid
from datetime import datetime
from typing import AsyncGenerator

import pytest
import pytest_asyncio

from tbhm.db.base import Base
from tbhm.db.models import Scan, ScanStatus, Target
from tbhm.db.session import engine


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator:
    """Create database session for testing."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    from tbhm.db.session import async_session_factory
    async with async_session_factory() as session:
        yield session
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def sample_target() -> Target:
    """Create a sample target."""
    return Target(
        id=uuid.uuid4(),
        name="Test Target",
        domain="example.com",
        company="Test Company",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


@pytest.fixture
def sample_scan() -> Scan:
    """Create a sample scan."""
    target_id = uuid.uuid4()
    return Scan(
        id=uuid.uuid4(),
        target_id=target_id,
        scan_type="subdomain",
        status=ScanStatus.PENDING,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


@pytest.fixture
def sample_target_id() -> uuid.UUID:
    """Return a sample target UUID."""
    return uuid.uuid4()


@pytest.fixture
def sample_scan_id() -> uuid.UUID:
    """Return a sample scan UUID."""
    return uuid.uuid4()