"""
Celery tasks for TBHM scanning operations.
"""

import asyncio
import json
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


def _update_scan_status(scan_id: str, status: str, results: Dict = None, error: str = None):
    """Update scan status using database session."""
    if not scan_id:
        return
    
    try:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_async_update_scan_status(scan_id, status, results, error))
        finally:
            loop.close()
        logger.info(f"Scan {scan_id} status updated to {status}")
    except Exception as e:
        logger.error(f"Failed to update scan {scan_id} status: {e}")


async def _async_update_scan_status(scan_id: str, status: str, results: Dict = None, error: str = None):
    """Async update scan status."""
    from tbhm.db.session import async_session_factory
    from tbhm.db.models import ScanStatus as ModelScanStatus
    
    status_map = {
        "running": ModelScanStatus.RUNNING,
        "completed": ModelScanStatus.COMPLETED,
        "failed": ModelScanStatus.FAILED,
    }
    
    async with async_session_factory() as session:
        from tbhm.workers.status import update_scan_status
        await update_scan_status(
            session,
            scan_id,
            status_map.get(status, ModelScanStatus.PENDING),
            results=results,
            error_message=error,
        )


def _make_status_callbacks(scan_id: str):
    """Create Celery callbacks for status updates."""
    def on_request():
        if scan_id:
            _update_scan_status(scan_id, "running")
    
    def on_success(result):
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
    
    def on_failure(exception, args, kwargs, einfo):
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(exception))
    
    return on_request, on_success, on_failure


@celery_app.task(bind=True)
def scan_subdomains(self, scan_id: str, target_id: str, domain: str, sources: list = None) -> Dict[str, Any]:
    """
    Subdomain enumeration scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..recon import run_subdomain_enum

    logger.info(f"Starting subdomain enumeration for {domain}")

    try:
        result = run_async(run_subdomain_enum(target_id, domain, sources))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"Subdomain scan completed: {result.get('total_found', 0)} found")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_fingerprint(self, scan_id: str, target_id: str, subdomains: list) -> Dict[str, Any]:
    """
    Web fingerprinting scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..recon import run_fingerprint

    logger.info(f"Starting fingerprint scan for {len(subdomains)} hosts")

    try:
        result = run_async(run_fingerprint(target_id, subdomains))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"Fingerprint scan completed: {result.get('live_count', 0)} live hosts")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_ip_discovery(self, scan_id: str, target_id: str, domain: str, company: str = None) -> Dict[str, Any]:
    """
    IP and ASN discovery scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..recon import run_ip_discovery

    logger.info(f"Starting IP discovery for {domain}")

    try:
        result = run_async(run_ip_discovery(target_id, domain, company))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"IP discovery completed")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def run_recon_workflow(
    self,
    scan_id: str,
    target_id: str,
    domain: str,
    company: str = None,
    workflow: str = "full",
) -> Dict[str, Any]:
    """
    Run full reconnaissance workflow combining all recon modules.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..recon import run_subdomain_enum, run_fingerprint, run_ip_discovery

    logger.info(f"Starting recon workflow for {domain}")

    try:
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

        if scan_id:
            _update_scan_status(scan_id, "completed", results=results)
        
        logger.info(f"Recon workflow completed")
        return results
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_directory(self, scan_id: str, target_id: str, url: str, wordlist: str = None) -> Dict[str, Any]:
    """
    Directory fuzzing scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..recon import run_directory_fuzz

    logger.info(f"Starting directory fuzzing for {url}")

    try:
        result = run_async(run_directory_fuzz(target_id, url, wordlist))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"Directory fuzz completed: {result.get('total', 0)} found")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_js_extraction(self, scan_id: str, target_id: str, domain: str) -> Dict[str, Any]:
    """
    JavaScript extraction scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..recon import run_js_extraction

    logger.info(f"Starting JS extraction for {domain}")

    try:
        result = run_async(run_js_extraction(target_id, domain))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"JS extraction completed: {result.get('js_files_count', 0)} files")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_port(self, scan_id: str, target_id: str, hosts: list, ports: str = None, rate: int = 1000) -> Dict[str, Any]:
    """
    Port scanning scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..recon import run_port_scan

    logger.info(f"Starting port scan for {len(hosts)} hosts")

    try:
        result = run_async(run_port_scan(target_id, hosts, ports, rate))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"Port scan completed: {result.get('open_ports', 0)} open ports")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_screenshots(self, scan_id: str, target_id: str, urls: list) -> Dict[str, Any]:
    """
    Screenshot capture scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..recon import run_screenshot_capture

    logger.info(f"Starting screenshot capture for {len(urls)} URLs")

    try:
        result = run_async(run_screenshot_capture(target_id, urls))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"Screenshot capture completed: {result.get('successful_captures', 0)} captures")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_vulnerabilities(self, scan_id: str, target_id: str, targets: list) -> Dict[str, Any]:
    """
    Vulnerability scanning task using Nuclei.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..vuln import run_vuln_scan

    logger.info(f"Starting vulnerability scan for {len(targets)} targets")

    try:
        result = run_async(run_vuln_scan(target_id, targets))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"Vulnerability scan completed: {result.get('total', 0)} found")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_idor(self, scan_id: str, target_id: str, endpoints: list, auth_token: str = None) -> Dict[str, Any]:
    """
    IDOR detection task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..vuln import run_idor_test

    logger.info(f"Starting IDOR test for {len(endpoints)} endpoints")

    try:
        result = run_async(run_idor_test(target_id, endpoints, auth_token))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"IDOR test completed: {result.get('vulnerabilities', 0)} found")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_ssrf(self, scan_id: str, target_id: str, endpoints: list, webhook_url: str = None) -> Dict[str, Any]:
    """
    SSRF testing task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..vuln import run_ssrf_test

    logger.info(f"Starting SSRF test for {len(endpoints)} endpoints")

    try:
        result = run_async(run_ssrf_test(target_id, endpoints, webhook_url))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"SSRF test completed: {result.get('vulnerable', 0)} found")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_heat_mapping(
    self,
    scan_id: str,
    target_id: str,
    vuln_results: dict,
    subdomain_data: list,
) -> Dict[str, Any]:
    """
    Generate vulnerability heat map.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..vuln import run_heat_mapping

    logger.info(f"Generating heat map for target {target_id}")

    try:
        result = run_async(run_heat_mapping(target_id, vuln_results, subdomain_data))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"Heat map generated: risk score {result.get('risk_score', 0)}")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_waf(self, scan_id: str, target_id: str, url: str) -> Dict[str, Any]:
    """
    WAF detection task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..exploit import run_waf_detection

    logger.info(f"Starting WAF detection for {url}")

    try:
        result = run_async(run_waf_detection(target_id, url))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"WAF detection completed: {result.get('waf', {}).get('waf_detected', False)}")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_dependency_confusion(
    self,
    scan_id: str,
    target_id: str,
    packages: list,
    ecosystem: str = "npm",
    internal_registry: str = None,
) -> Dict[str, Any]:
    """
    Dependency confusion scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..exploit import run_dependency_scan

    logger.info(f"Starting dependency confusion scan for {len(packages)} packages")

    try:
        result = run_async(run_dependency_scan(
            target_id, packages, ecosystem, internal_registry
        ))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"Dependency scan completed: {result.get('vulnerable', 0)} vulnerable")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_sqli(self, scan_id: str, target_id: str, endpoints: list) -> Dict[str, Any]:
    """
    SQL injection scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..vuln import run_sqli_scan

    logger.info(f"Starting SQL injection scan for {len(endpoints)} endpoints")

    try:
        result = run_async(run_sqli_scan(target_id, endpoints))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"SQLi scan completed: {result.get('vulnerable', 0)} found")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_cmdi(self, scan_id: str, target_id: str, endpoints: list) -> Dict[str, Any]:
    """
    Command injection scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..vuln import run_cmdi_scan

    logger.info(f"Starting command injection scan for {len(endpoints)} endpoints")

    try:
        result = run_async(run_cmdi_scan(target_id, endpoints))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"CMDi scan completed: {result.get('vulnerable', 0)} found")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def scan_authenticated(
    self,
    scan_id: str,
    target_id: str,
    endpoints: list,
    token: str,
    token_type: str = "bearer",
) -> Dict[str, Any]:
    """
    Authenticated vulnerability scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..vuln import run_authenticated_scan

    logger.info(f"Starting authenticated scan for {len(endpoints)} endpoints")

    try:
        result = run_async(run_authenticated_scan(target_id, endpoints, token, token_type))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"Auth scan completed: {result.get('accessible', 0)} accessible")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def prioritize_findings(
    self,
    scan_id: str,
    target_id: str,
    findings: list,
    context: dict = None,
) -> Dict[str, Any]:
    """
    Prioritize and generate remediation guidance task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    from ..vuln import run_prioritization

    logger.info(f"Prioritizing {len(findings)} findings for target {target_id}")

    try:
        result = run_async(run_prioritization(target_id, findings, context))
        
        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"Prioritization completed: {result.get('total_findings', 0)} findings")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(bind=True)
def run_scan(self, scan_id: str, scan_type: str, target: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a generic scan task.
    """
    if scan_id:
        _update_scan_status(scan_id, "running")
    
    logger.info(f"Starting scan {scan_id} of type {scan_type} for target {target}")

    try:
        result = {
            "scan_id": scan_id,
            "scan_type": scan_type,
            "status": "completed",
        }

        if scan_id:
            _update_scan_status(scan_id, "completed", results=result)
        
        logger.info(f"Completed scan {scan_id}")
        return result
    except Exception as e:
        if scan_id:
            _update_scan_status(scan_id, "failed", error=str(e))
        raise