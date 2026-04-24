"""
Database helper for workers to update scan status.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tbhm.db.models import Scan, ScanStatus

logger = logging.getLogger(__name__)


async def update_scan_status(
    db: AsyncSession,
    scan_id: str,
    status: ScanStatus,
    results: Optional[Dict[str, Any]] = None,
    error_message: Optional[str] = None,
) -> Optional[Scan]:
    """Update scan status in database."""
    try:
        scan_uuid = uuid.UUID(str(scan_id))
        result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
        scan = result.scalar_one_or_none()
        
        if scan is None:
            logger.error(f"Scan {scan_id} not found")
            return None
        
        scan.status = status
        
        if status == ScanStatus.RUNNING:
            scan.started_at = datetime.utcnow()
        elif status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            scan.completed_at = datetime.utcnow()
        
        if results is not None:
            scan.results = json.dumps(results)
        
        if error_message is not None:
            scan.error_message = error_message
        
        await db.commit()
        await db.refresh(scan)
        
        logger.info(f"Scan {scan_id} status updated to {status.value}")
        return scan
    
    except Exception as e:
        logger.error(f"Failed to update scan {scan_id}: {e}")
        await db.rollback()
        return None


async def mark_scan_pending(
    db: AsyncSession,
    scan_id: str,
) -> Optional[Scan]:
    """Mark scan as pending."""
    return await update_scan_status(db, scan_id, ScanStatus.PENDING)


async def mark_scan_running(
    db: AsyncSession,
    scan_id: str,
) -> Optional[Scan]:
    """Mark scan as running."""
    return await update_scan_status(db, scan_id, ScanStatus.RUNNING)


async def mark_scan_completed(
    db: AsyncSession,
    scan_id: str,
    results: Optional[Dict[str, Any]] = None,
) -> Optional[Scan]:
    """Mark scan as completed with results."""
    return await update_scan_status(
        db, scan_id, ScanStatus.COMPLETED, results=results
    )


async def mark_scan_failed(
    db: AsyncSession,
    scan_id: str,
    error_message: str,
) -> Optional[Scan]:
    """Mark scan as failed with error message."""
    return await update_scan_status(
        db, scan_id, ScanStatus.FAILED, error_message=error_message
    )


async def mark_scan_cancelled(
    db: AsyncSession,
    scan_id: str,
) -> Optional[Scan]:
    """Mark scan as cancelled."""
    return await update_scan_status(db, scan_id, ScanStatus.CANCELLED)