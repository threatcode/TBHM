"""
Pydantic schemas for TBHM API.
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class TargetBase(BaseModel):
    """Base target schema."""

    name: str = Field(..., min_length=1, max_length=255)
    domain: str = Field(..., min_length=1, max_length=512)
    description: Optional[str] = None
    company: Optional[str] = Field(None, max_length=255)


class TargetCreate(TargetBase):
    """Schema for target creation."""


class TargetUpdate(BaseModel):
    """Schema for target updates."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    domain: Optional[str] = Field(None, min_length=1, max_length=512)
    description: Optional[str] = None
    company: Optional[str] = Field(None, max_length=255)


class TargetResponse(TargetBase):
    """Schema for target response."""

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanStatus(str):
    """Scan status enumeration for schema."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanBase(BaseModel):
    """Base scan schema."""

    target_id: uuid.UUID
    scan_type: str = Field(..., min_length=1, max_length=100)


class ScanCreate(ScanBase):
    """Schema for scan creation."""


class ScanUpdate(BaseModel):
    """Schema for scan updates."""

    status: Optional[str] = None
    results: Optional[str] = None
    error_message: Optional[str] = None


class ScanResponse(ScanBase):
    """Schema for scan response."""

    id: uuid.UUID
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    results: Optional[str]
    error_message: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)