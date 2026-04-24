"""
Asset models for Neo4j relationship mapping.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AssetType(str, Enum):
    """Asset type enumeration."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"


class AssetBase(BaseModel):
    """Base asset schema."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    asset_type: AssetType
    target_id: str
    discovered_by: Optional[str] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict = Field(default_factory=dict)


class AssetCreate(AssetBase):
    """Schema for asset creation."""


class AssetResponse(AssetBase):
    """Schema for asset response."""

    model_config = {"from_attributes": True}


class DomainAsset(AssetBase):
    """Domain asset model."""

    registrar: Optional[str] = None
    registrant: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    nameservers: list[str] = Field(default_factory=list)
    whois_data: Optional[dict] = None


class SubdomainAsset(AssetBase):
    """Subdomain asset model."""

    domain_id: Optional[str] = None
    ip_addresses: list[str] = Field(default_factory=list)
    http_ports: list[int] = Field(default_factory=list)
    https_ports: list[int] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)
    is_live: bool = True
    title: Optional[str] = None
    favicon_hash: Optional[str] = None
    headers: Optional[dict] = None


class IPAsset(BaseModel):
    """IP address asset model."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    address: str
    target_id: str
    asn: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    hosting: bool = False
    is_cdn: bool = False
    metadata: dict = Field(default_factory=dict)


class ServiceAsset(BaseModel):
    """Service asset model."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ip_id: str
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    service_banner: Optional[str] = None
    is_rdp: bool = False
    is_smb: bool = False
    is_ssh: bool = False
    is_http: bool = False
    is_https: bool = False
    metadata: dict = Field(default_factory=dict)


class RelationshipBase(BaseModel):
    """Base relationship schema."""

    source_id: str
    target_id: str
    rel_type: str
    properties: dict = Field(default_factory=dict)


class DNSRecord(BaseModel):
    """DNS record model."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain_id: str
    record_type: str
    name: str
    value: str
    priority: Optional[int] = None
    ttl: Optional[int] = None


class Technology(BaseModel):
    """Technology detection model."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subdomain_id: str
    name: str
    category: str
    version: Optional[str] = None
    confidence: float = 1.0