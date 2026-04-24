"""
Main API router for v1 endpoints.
"""

from fastapi import APIRouter

from .endpoints import health, targets, scans, recon

api_router = APIRouter()

# Include endpoint routers
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(targets.router, prefix="/targets", tags=["targets"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(recon.router, prefix="/recon", tags=["recon"])