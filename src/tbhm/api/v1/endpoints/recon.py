"""
Scan execution endpoints.
"""

import uuid
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from tbhm.api.deps import get_db
from tbhm.crud import crud_scan
from tbhm.schemas import ScanCreate, ScanResponse, ScanUpdate
from tbhm.db.models import ScanStatus
from tbhm.workers.tasks import scan_subdomains, scan_fingerprint, run_recon_workflow

router = APIRouter()


class StartReconRequest(BaseModel):
    """Request model for starting recon scans."""

    target_id: uuid.UUID
    scan_type: str
    domain: str
    company: Optional[str] = None
    sources: Optional[List[str]] = None
    workflow: Optional[str] = "full"


class ReconStatusResponse(BaseModel):
    """Response for recon status."""

    scan_id: uuid.UUID
    status: str
    task_id: Optional[str] = None


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
async def start_recon_scan(
    request: StartReconRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Start a reconnaissance scan on a target.
    """
    scan_in = ScanCreate(
        target_id=request.target_id,
        scan_type=f"recon_{request.scan_type}",
    )
    scan = await crud_scan.create_scan(db, scan_in)

    task = None
    if request.scan_type == "subdomains":
        task = scan_subdomains.apply_async(
            args=[str(request.target_id), request.domain, request.sources]
        )
    elif request.scan_type == "fingerprint":
        subdomain_scan = await crud_scan.get_scans_by_target(
            db, request.target_id, limit=1
        )
        if subdomain_scan:
            subdomains = []
            task = scan_fingerprint.apply_async(
                args=[str(request.target_id), subdomains]
            )
    elif request.scan_type == "workflow":
        task = run_recon_workflow.apply_async(
            args=[
                str(request.target_id),
                request.domain,
                request.company,
                request.workflow,
            ]
        )

    scan.task_id = task.id if task else None
    await db.commit()

    return {
        "scan_id": scan.id,
        "status": "started",
        "task_id": task.id if task else None,
    }


@router.post("/cancel/{scan_id}")
async def cancel_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running scan."""
    scan = await crud_scan.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status == ScanStatus.RUNNING:
        scan.status = ScanStatus.CANCELLED
        await db.commit()

    return {"message": "Scan cancelled"}


@router.get("/{scan_id}/results")
async def get_scan_results(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get results for a completed scan."""
    scan = await crud_scan.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "results": scan.results,
    }