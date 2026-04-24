"""
Celery tasks for TBHM scanning operations.
"""

import asyncio
import logging
from typing import Any, Dict

from .celery_config import celery_app

logger = logging.getLogger(__name__)


def run_async(coro):
    """Run async function in sync context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(bind=True)
def scan_subdomains(self, target_id: str, domain: str, sources: list = None) -> Dict[str, Any]:
    """
    Subdomain enumeration scan task.
    """
    from ..recon import run_subdomain_enum

    logger.info(f"Starting subdomain enumeration for {domain}")

    result = run_async(run_subdomain_enum(target_id, domain, sources))

    logger.info(f"Subdomain scan completed: {result.get('total_found', 0)} found")
    return result


@celery_app.task(bind=True)
def scan_fingerprint(self, target_id: str, subdomains: list) -> Dict[str, Any]:
    """
    Web fingerprinting scan task.
    """
    from ..recon import run_fingerprint

    logger.info(f"Starting fingerprint scan for {len(subdomains)} hosts")

    result = run_async(run_fingerprint(target_id, subdomains))

    logger.info(f"Fingerprint scan completed: {result.get('live_count', 0)} live hosts")
    return result


@celery_app.task(bind=True)
def scan_ip_discovery(self, target_id: str, domain: str, company: str = None) -> Dict[str, Any]:
    """
    IP and ASN discovery scan task.
    """
    from ..recon import run_ip_discovery

    logger.info(f"Starting IP discovery for {domain}")

    result = run_async(run_ip_discovery(target_id, domain, company))

    logger.info(f"IP discovery completed")
    return result


@celery_app.task(bind=True)
def run_recon_workflow(
    self,
    target_id: str,
    domain: str,
    company: str = None,
    workflow: str = "full",
) -> Dict[str, Any]:
    """
    Run full reconnaissance workflow combining all recon modules.
    """
    from ..recon import run_subdomain_enum, run_fingerprint, run_ip_discovery

    logger.info(f"Starting recon workflow for {domain}")

    results = {
        "target_id": target_id,
        "domain": domain,
        "workflow": workflow,
    }

    if workflow in ["full", "subdomains"]:
        subdomain_result = run_async(run_subdomain_enum(target_id, domain))
        results["subdomains"] = subdomain_result

        if workflow == "full" and subdomain_result.get("subdomains"):
            fingerprint_result = run_async(
                run_fingerprint(target_id, subdomain_result["subdomains"])
            )
            results["fingerprint"] = fingerprint_result

    if workflow in ["full", "ip"]:
        ip_result = run_async(run_ip_discovery(target_id, domain, company))
        results["ip_discovery"] = ip_result

    logger.info(f"Recon workflow completed")
    return results


@celery_app.task(bind=True)
def run_scan(self, scan_id: str, scan_type: str, target: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a generic scan task.
    """
    logger.info(f"Starting scan {scan_id} of type {scan_type} for target {target}")

    result = {
        "scan_id": scan_id,
        "scan_type": scan_type,
        "status": "completed",
    }

    logger.info(f"Completed scan {scan_id}")
    return result