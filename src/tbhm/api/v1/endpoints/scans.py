"""
Scan management endpoints.
"""

import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...deps import get_db
from tbhm.crud import crud_scan
from tbhm.schemas import ScanCreate, ScanResponse, ScanUpdate

router = APIRouter()


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    """List all scans."""
    scans = await crud_scan.get_scans(db, skip=skip, limit=limit)
    return scans


@router.get("/target/{target_id}", response_model=List[ScanResponse])
async def get_scans_by_target(
    target_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    """Get scans for a specific target."""
    scans = await crud_scan.get_scans_by_target(
        db, target_id, skip=skip, limit=limit
    )
    return scans


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a scan by ID."""
    scan = await crud_scan.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_in: ScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new scan."""
    scan = await crud_scan.create_scan(db, scan_in)
    return scan


@router.patch("/{scan_id}", response_model=ScanResponse)
async def update_scan(
    scan_id: uuid.UUID,
    scan_in: ScanUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update a scan."""
    scan = await crud_scan.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = await crud_scan.update_scan(db, scan, scan_in)
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan."""
    deleted = await crud_scan.delete_scan(db, scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")