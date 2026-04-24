"""
CRUD operations for scans.
"""

import uuid
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Scan, ScanStatus
from ..schemas import ScanCreate, ScanUpdate


async def get_scan(db: AsyncSession, scan_id: uuid.UUID) -> Optional[Scan]:
    """Get a scan by ID."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    return result.scalar_one_or_none()


async def get_scans(
    db: AsyncSession, skip: int = 0, limit: int = 100
) -> List[Scan]:
    """Get a list of scans."""
    result = await db.execute(select(Scan).offset(skip).limit(limit))
    return list(result.scalars().all())


async def get_scans_by_target(
    db: AsyncSession, target_id: uuid.UUID, skip: int = 0, limit: int = 100
) -> List[Scan]:
    """Get scans for a specific target."""
    result = await db.execute(
        select(Scan)
        .where(Scan.target_id == target_id)
        .offset(skip)
        .limit(limit)
    )
    return list(result.scalars().all())


async def create_scan(db: AsyncSession, scan_in: ScanCreate) -> Scan:
    """Create a new scan."""
    scan = Scan(
        target_id=scan_in.target_id,
        scan_type=scan_in.scan_type,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


async def update_scan(
    db: AsyncSession,
    scan: Scan,
    scan_in: ScanUpdate,
) -> Scan:
    """Update a scan."""
    update_data = scan_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(scan, field, value)
    await db.commit()
    await db.refresh(scan)
    return scan


async def delete_scan(db: AsyncSession, scan_id: uuid.UUID) -> bool:
    """Delete a scan."""
    scan = await get_scan(db, scan_id)
    if scan:
        await db.delete(scan)
        await db.commit()
        return True
    return False