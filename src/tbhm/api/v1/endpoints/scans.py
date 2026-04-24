"""
Scan management endpoints.
"""

import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...deps import get_db
from tbhm.crud import crud_scan
from tbhm.schemas import ScanCreate, ScanResponse, ScanUpdate
from tbhm.workers import tasks

router = APIRouter()


class ScanTriggerRequest(BaseModel):
    """Request to trigger a scan."""
    target_id: str
    scan_type: str
    options: Optional[dict] = {}


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


@router.post("/trigger", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(
    request: ScanTriggerRequest,
    db: AsyncSession = Depends(get_db),
):
    """Trigger a vulnerability scan."""
    target_id = request.target_id
    options = request.options or {}

    result = _execute_scan_task(request.scan_type, target_id, options)

    return {
        "task_id": result.id,
        "status": "started",
        "scan_type": request.scan_type,
    }


def _execute_scan_task(scan_type: str, target_id: str, options: dict):
    """Execute the appropriate scan task based on type."""
    endpoints = options.get("endpoints", [])
    token = options.get("token")
    token_type = options.get("token_type", "bearer")
    findings = options.get("findings", [])
    context = options.get("context")

    if scan_type == "sqli":
        return tasks.scan_sqli.delay(target_id, endpoints)
    elif scan_type == "cmdi":
        return tasks.scan_cmdi.delay(target_id, endpoints)
    elif scan_type == "authenticated":
        return tasks.scan_authenticated.delay(target_id, endpoints, token, token_type)
    elif scan_type == "prioritize":
        return tasks.prioritize_findings.delay(target_id, findings, context)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scan type: {scan_type}"
        )


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