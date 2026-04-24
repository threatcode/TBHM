"""
IDOR (Insecure Direct Object Reference) detection module.
"""

import logging
import random
import string
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class IDORDetector:
    """Detect IDOR vulnerabilities."""

    def __init__(self):
        self.id_patterns = [
            r"/(api|user|order|item|post|product|ref|inv|id)\s*/\d+",
            r"(?:ids?|ref|inv|order|user|post)\s*=\s*\d+",
            r"uuid\s*=\s*[\w-]{36}",
        ]

    def generate_test_ids(self, base_id: int, count: int = 10) -> List[str]:
        """Generate test IDs around the base ID."""
        test_ids = [str(base_id)]

        for offset in range(1, count + 1):
            test_ids.append(str(base_id + offset))
            test_ids.append(str(base_id - offset))
            test_ids.append(str(base_id * random.randint(2, 10)))
            test_ids.append(str(random.randint(100000, 999999)))

        return list(set(test_ids))

    def test_endpoint(
        self,
        endpoint: str,
        method: str = "GET",
        auth_token: Optional[str] = None,
    ) -> List[Dict]:
        """Test an endpoint for IDOR."""
        results = []

        try:
            endpoint_lower = endpoint.lower()
            if "id=" in endpoint_lower:
                base_id = endpoint.split("id=")[1].split("&")[0]
                test_ids = self.generate_test_ids(int(base_id))
            else:
                return results

            headers = {}
            if auth_token:
                headers["Authorization"] = f"Bearer {auth_token}"

            for test_id in test_ids[:10]:
                test_endpoint = endpoint.replace(f"id={base_id}", f"id={test_id}")

                result = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "-X", method, test_endpoint],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    status = int(result.stdout.strip())
                    results.append({
                        "test_id": test_id,
                        "original_id": base_id,
                        "status_code": status,
                        "vulnerable": status == 200,
                    })
        except Exception as e:
            logger.error(f"Error testing IDOR: {e}")

        return results

    def find_id_endpoints(self, js_content: str) -> List[str]:
        """Find potential IDOR endpoints in JS."""
        import re

        endpoints = []
        for pattern in self.id_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                endpoints.append(match.group(0))

        return endpoints


async def run_idor_test(
    target_id: str,
    endpoints: List[str],
    auth_token: Optional[str] = None,
) -> dict:
    """Run IDOR tests on endpoints."""
    detector = IDORDetector()

    all_results = []
    vulnerabilities_found = []

    for endpoint in endpoints:
        results = detector.test_endpoint(endpoint, auth_token=auth_token)
        all_results.extend(results)

        vulnerable = any(r.get("vulnerable", False) for r in results)
        if vulnerable:
            vulnerabilities_found.append({
                "endpoint": endpoint,
                "test_results": results,
            })

    return {
        "target_id": target_id,
        "total_tests": len(all_results),
        "vulnerabilities": len(vulnerabilities_found),
        "findings": vulnerabilities_found,
    }