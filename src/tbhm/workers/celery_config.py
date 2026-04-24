"""
Celery configuration for TBHM.
"""

from celery import Celery
from celery.exceptions import MaxRetriesExceededError

from ..core.config import settings

celery_app = Celery(
    "tbhm",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["tbhm.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,
    task_soft_time_limit=25 * 60,
    task_default_retry_delay=60,
    task_max_retries=3,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)

celery_app.conf.task_routes = {
    "tbhm.workers.tasks.scan_*": {"queue": "scans"},
    "tbhm.workers.tasks.run_*": {"queue": "scans"},
    "tbhm.workers.tasks.prioritize_*": {"queue": "analysis"},
}


class TaskRetryError(Exception):
    """Custom exception for task retry scenarios."""
    pass


def create_retry_handler(task_func, max_retries: int = 3, default_delay: int = 60):
    """
    Create a retry handler wrapper for Celery tasks.
    
    Args:
        task_func: The task function to wrap
        max_retries: Maximum number of retry attempts
        default_delay: Default delay between retries in seconds
    """
    def retry_handler(self, *args, **kwargs):
        try:
            return task_func(self, *args, **kwargs)
        except Exception as e:
            if self.request.retries >= max_retries:
                self.update_state(
                    state="FAILURE",
                    meta={
                        "error": str(e),
                        "retries_exhausted": True,
                    }
                )
                raise
            raise self.retry(exc=e, countdown=default_delay * (self.request.retries + 1))
    
    return retry_handler