"""
CRUD operations for targets.
"""

import uuid
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Target
from ..schemas import TargetCreate, TargetUpdate


async def get_target(db: AsyncSession, target_id: uuid.UUID) -> Optional[Target]:
    """Get a target by ID."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    return result.scalar_one_or_none()


async def get_targets(
    db: AsyncSession, skip: int = 0, limit: int = 100
) -> List[Target]:
    """Get a list of targets."""
    result = await db.execute(select(Target).offset(skip).limit(limit))
    return list(result.scalars().all())


async def create_target(db: AsyncSession, target_in: TargetCreate) -> Target:
    """Create a new target."""
    target = Target(
        name=target_in.name,
        domain=target_in.domain,
        description=target_in.description,
        company=target_in.company,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


async def update_target(
    db: AsyncSession,
    target: Target,
    target_in: TargetUpdate,
) -> Target:
    """Update a target."""
    update_data = target_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(target, field, value)
    await db.commit()
    await db.refresh(target)
    return target


async def delete_target(db: AsyncSession, target_id: uuid.UUID) -> bool:
    """Delete a target."""
    target = await get_target(db, target_id)
    if target:
        await db.delete(target)
        await db.commit()
        return True
    return False