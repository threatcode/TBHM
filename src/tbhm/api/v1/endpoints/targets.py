"""
Targets management endpoints.
"""

import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...deps import get_db
from tbhm.crud import crud_target
from tbhm.schemas import TargetCreate, TargetResponse, TargetUpdate

router = APIRouter()


@router.get("/", response_model=List[TargetResponse])
async def list_targets(
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    """List all targets."""
    targets = await crud_target.get_targets(db, skip=skip, limit=limit)
    return targets


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a target by ID."""
    target = await crud_target.get_target(db, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.post("/", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(
    target_in: TargetCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new target."""
    target = await crud_target.create_target(db, target_in)
    return target


@router.patch("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: uuid.UUID,
    target_in: TargetUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update a target."""
    target = await crud_target.get_target(db, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target = await crud_target.update_target(db, target, target_in)
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a target."""
    deleted = await crud_target.delete_target(db, target_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Target not found")