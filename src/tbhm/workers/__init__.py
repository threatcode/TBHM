"""
Workers package for Celery tasks.
"""

from .celery_config import celery_app
from .tasks import run_scan

__all__ = ["celery_app", "run_scan"]