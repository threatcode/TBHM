"""
CRUD package.
"""

from .crud_target import (
    create_target,
    delete_target,
    get_target,
    get_targets,
    update_target,
)
from .crud_scan import (
    create_scan,
    delete_scan,
    get_scan,
    get_scans,
    get_scans_by_target,
    update_scan,
)

__all__ = [
    "get_target",
    "get_targets",
    "create_target",
    "update_target",
    "delete_target",
    "get_scan",
    "get_scans",
    "get_scans_by_target",
    "create_scan",
    "update_scan",
    "delete_scan",
]