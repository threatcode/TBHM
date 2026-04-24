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
def scan_directory(self, target_id: str, url: str, wordlist: str = None) -> Dict[str, Any]:
    """
    Directory fuzzing scan task.
    """
    from ..recon import run_directory_fuzz

    logger.info(f"Starting directory fuzzing for {url}")

    result = run_async(run_directory_fuzz(target_id, url, wordlist))

    logger.info(f"Directory fuzz completed: {result.get('total', 0)} found")
    return result


@celery_app.task(bind=True)
def scan_js_extraction(self, target_id: str, domain: str) -> Dict[str, Any]:
    """
    JavaScript extraction scan task.
    """
    from ..recon import run_js_extraction

    logger.info(f"Starting JS extraction for {domain}")

    result = run_async(run_js_extraction(target_id, domain))

    logger.info(f"JS extraction completed: {result.get('js_files_count', 0)} files")
    return result


@celery_app.task(bind=True)
def scan_port(self, target_id: str, hosts: list, ports: str = None, rate: int = 1000) -> Dict[str, Any]:
    """
    Port scanning scan task.
    """
    from ..recon import run_port_scan

    logger.info(f"Starting port scan for {len(hosts)} hosts")

    result = run_async(run_port_scan(target_id, hosts, ports, rate))

    logger.info(f"Port scan completed: {result.get('open_ports', 0)} open ports")
    return result


@celery_app.task(bind=True)
def scan_screenshots(self, target_id: str, urls: list) -> Dict[str, Any]:
    """
    Screenshot capture scan task.
    """
    from ..recon import run_screenshot_capture

    logger.info(f"Starting screenshot capture for {len(urls)} URLs")

    result = run_async(run_screenshot_capture(target_id, urls))

    logger.info(f"Screenshot capture completed: {result.get('successful_captures', 0)} captures")
    return result


@celery_app.task(bind=True)
def scan_vulnerabilities(self, target_id: str, targets: list) -> Dict[str, Any]:
    """
    Vulnerability scanning task using Nuclei.
    """
    from ..vuln import run_vuln_scan

    logger.info(f"Starting vulnerability scan for {len(targets)} targets")

    result = run_async(run_vuln_scan(target_id, targets))

    logger.info(f"Vulnerability scan completed: {result.get('total', 0)} found")
    return result


@celery_app.task(bind=True)
def scan_idor(self, target_id: str, endpoints: list, auth_token: str = None) -> Dict[str, Any]:
    """
    IDOR detection task.
    """
    from ..vuln import run_idor_test

    logger.info(f"Starting IDOR test for {len(endpoints)} endpoints")

    result = run_async(run_idor_test(target_id, endpoints, auth_token))

    logger.info(f"IDOR test completed: {result.get('vulnerabilities', 0)} found")
    return result


@celery_app.task(bind=True)
def scan_ssrf(self, target_id: str, endpoints: list, webhook_url: str = None) -> Dict[str, Any]:
    """
    SSRF testing task.
    """
    from ..vuln import run_ssrf_test

    logger.info(f"Starting SSRF test for {len(endpoints)} endpoints")

    result = run_async(run_ssrf_test(target_id, endpoints, webhook_url))

    logger.info(f"SSRF test completed: {result.get('vulnerable', 0)} found")
    return result


@celery_app.task(bind=True)
def scan_heat_mapping(
    self,
    target_id: str,
    vuln_results: dict,
    subdomain_data: list,
) -> Dict[str, Any]:
    """
    Generate vulnerability heat map.
    """
    from ..vuln import run_heat_mapping

    logger.info(f"Generating heat map for target {target_id}")

    result = run_async(run_heat_mapping(target_id, vuln_results, subdomain_data))

    logger.info(f"Heat map generated: risk score {result.get('risk_score', 0)}")
    return result


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