"""
Change monitoring and diffing engine.
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class DiffEngine:
    """Detect changes in scan results."""

    def __init__(self):
        self.history_file = "./data/scan_history.json"

    def compute_hash(self, data: Dict) -> str:
        """Compute hash of data."""
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()

    def diff_subdomains(
        self,
        old_subdomains: List[str],
        new_subdomains: List[str],
    ) -> Dict:
        """
        Diff subdomain lists.

        Args:
            old_subdomains: Previous subdomain list
            new_subdomains: New subdomain list
        """
        old_set = set(old_subdomains)
        new_set = set(new_subdomains)

        added = new_set - old_set
        removed = old_set - new_set
        unchanged = old_set & new_set

        return {
            "added": list(added),
            "removed": list(removed),
            "unchanged": list(unchanged),
            "added_count": len(added),
            "removed_count": len(removed),
            "total_count": len(new_set),
        }

    def diff_vulnerabilities(
        self,
        old_vulns: List[Dict],
        new_vulns: List[Dict],
    ) -> Dict:
        """Diff vulnerability lists."""
        old_by_name = {v.get("name", ""): v for v in old_vulns}
        new_by_name = {v.get("name", ""): v for v in new_vulns}

        old_names = set(old_by_name.keys())
        new_names = set(new_by_name.keys())

        added = new_names - old_names
        resolved = old_names - new_names

        new_details = [new_by_name[name] for name in added]
        resolved_details = [old_by_name[name] for name in resolved]

        return {
            "new_vulnerabilities": new_details,
            "resolved_vulnerabilities": resolved_details,
            "new_count": len(added),
            "resolved_count": len(resolved),
        }

    def diff_services(
        self,
        old_services: List[Dict],
        new_services: List[Dict],
    ) -> Dict:
        """Diff service lists."""
        old_ips = {f"{s.get('host')}:{s.get('port')}": s for s in old_services}
        new_ips = {f"{s.get('host')}:{s.get('port')}": s for s in new_services}

        old_set = set(old_ips.keys())
        new_set = set(new_ips.keys())

        new_services = [new_ips[ip] for ip in new_set - old_set]
        removed_services = [old_ips[ip] for ip in old_set - new_set]

        return {
            "new_services": new_services,
            "removed_services": removed_services,
            "new_count": len(new_services),
        }


class ChangeMonitor:
    """Monitor for significant changes."""

    def __init__(self):
        self.thresholds = {
            "new_subdomains": 5,
            "new_vulns": 1,
            "critical_vulns": 1,
            "new_services": 3,
        }

    def is_significant_change(
        self,
        diff_result: Dict,
        change_type: str,
    ) -> bool:
        """Determine if change is significant."""
        threshold = self.thresholds.get(change_type, 0)

        if change_type == "new_subdomains":
            return diff_result.get("added_count", 0) >= threshold
        elif change_type == "new_vulns":
            return diff_result.get("new_count", 0) >= threshold
        elif change_type == "critical_vulns":
            new_critical = any(
                v.get("severity") == "critical"
                for v in diff_result.get("new_vulnerabilities", [])
            )
            return new_critical
        elif change_type == "new_services":
            return diff_result.get("new_count", 0) >= threshold

        return False

    def generate_alert(
        self,
        target_id: str,
        diff_result: Dict,
        change_type: str,
    ) -> Dict:
        """Generate alert for significant change."""
        return {
            "target_id": target_id,
            "change_type": change_type,
            "timestamp": datetime.utcnow().isoformat(),
            "significant": self.is_significant_change(diff_result, change_type),
            "details": diff_result,
        }


class ScanScheduler:
    """Schedule recurring scans."""

    def __init__(self):
        self.intervals = {
            "hourly": timedelta(hours=1),
            "daily": timedelta(days=1),
            "weekly": timedelta(weeks=1),
            "monthly": timedelta(days=30),
        }

    def should_rescan(
        self,
        last_scan: datetime,
        interval: str = "daily",
    ) -> bool:
        """Check if rescan is due."""
        interval_delta = self.intervals.get(interval, timedelta(days=1))
        next_scan = last_scan + interval_delta

        return datetime.utcnow() >= next_scan

    def calculate_next_scan(
        self,
        last_scan: datetime,
        interval: str = "daily",
    ) -> datetime:
        """Calculate next scheduled scan time."""
        interval_delta = self.intervals.get(interval, timedelta(days=1))
        return last_scan + interval_delta


async def run_diff_analysis(
    target_id: str,
    current_results: Dict,
    previous_results: Optional[Dict] = None,
) -> dict:
    """Run diff analysis between scans."""
    diff_engine = DiffEngine()
    change_monitor = ChangeMonitor()

    results = {
        "target_id": target_id,
        "timestamp": datetime.utcnow().isoformat(),
        "changes": {},
    }

    if previous_results is None:
        return results

    if "subdomains" in current_results and "subdomains" in previous_results:
        subdomain_diff = diff_engine.diff_subdomains(
            previous_results["subdomains"].get("subdomains", []),
            current_results["subdomains"].get("subdomains", []),
        )
        results["changes"]["subdomains"] = subdomain_diff

        alert = change_monitor.generate_alert(
            target_id, subdomain_diff, "new_subdomains"
        )
        results["alerts"] = [alert] if alert.get("significant") else []

    if "vulnerabilities" in current_results and "vulnerabilities" in previous_results:
        vuln_diff = diff_engine.diff_vulnerabilities(
            previous_results["vulnerabilities"].get("vulnerabilities", []),
            current_results["vulnerabilities"].get("vulnerabilities", []),
        )
        results["changes"]["vulnerabilities"] = vuln_diff

    return results