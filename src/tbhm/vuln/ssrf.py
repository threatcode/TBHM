"""
SSRF (Server-Side Request Forgery) testing module.
"""

import json
import logging
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class SSRFTester:
    """Test for SSRF vulnerabilities."""

    def __init__(self):
        self.test_urls = [
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://metadata.google.internal",
            "http://169.254.169.254",
            "http://metadata.googleusercontent.com",
        ]
        self.internal_domains = [
            "internal.local",
            "stage.internal",
            "dev.internal",
            "test.internal",
            "admin.internal",
            "localtest.me",
        ]
        self.internal_ips = [
            "10.0.0.1",
            "10.0.0.2",
            "10.0.1.1",
            "172.16.0.1",
            "172.16.0.2",
            "192.168.0.1",
            "192.168.1.1",
        ]

    async def test_endpoint(
        self,
        endpoint: str,
        webhook_url: Optional[str] = None,
    ) -> Dict:
        """Test an endpoint for SSRF."""
        results = {
            "endpoint": endpoint,
            "tests": [],
            "vulnerable": False,
        }

        for test_url in self.test_urls:
            try:
                cmd = [
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "-X", "GET",
                    "-G",
                    f"{endpoint}?url={test_url}",
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    status = int(result.stdout.strip())
                    results["tests"].append({
                        "test_url": test_url,
                        "status_code": status,
                        "potential": status in [200, 201, 302],
                    })
            except Exception as e:
                logger.debug(f"Error testing {test_url}: {e}")

        for ip in self.internal_ips:
            try:
                cmd = [
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "-X", "GET",
                    "-G",
                    f"{endpoint}?host={ip}",
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    status = int(result.stdout.strip())
                    results["tests"].append({
                        "test_url": ip,
                        "status_code": status,
                        "potential": status in [200, 201, 302],
                    })
            except Exception as e:
                logger.debug(f"Error testing {ip}: {e}")

        vulnerable_count = sum(1 for t in results["tests"] if t.get("potential"))
        results["vulnerable"] = vulnerable_count > 0

        return results


async def run_ssrf_test(
    target_id: str,
    endpoints: List[str],
    webhook_url: Optional[str] = None,
) -> dict:
    """Run SSRF tests on endpoints."""
    tester = SSRFTester()

    all_results = []
    vulnerable_count = 0

    for endpoint in endpoints:
        result = await tester.test_endpoint(endpoint, webhook_url)
        all_results.append(result)

        if result.get("vulnerable"):
            vulnerable_count += 1

    return {
        "target_id": target_id,
        "total_endpoints": len(endpoints),
        "vulnerable": vulnerable_count,
        "results": all_results,
    }