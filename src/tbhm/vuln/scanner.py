"""
Vulnerability scanning module using Nuclei.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_TEMPLATES = [
    "cves/",
    "vulnerabilities/",
    "exposed-panels/",
    "exposed-files/",
    "misconfiguration/",
    "default-credentials/",
    "file/",
]


class NucleiScanner:
    """Vulnerability scanning using Nuclei."""

    def __init__(self, severity_filter: Optional[List[str]] = None):
        self.severity_filter = severity_filter or ["critical", "high", "medium"]
        self.templates_dir = Path.home() / ".nuclei-templates"

    async def scan(
        self,
        target: str,
        templates: Optional[List[str]] = None,
        rate: int = 150,
        timeout: int = 300,
    ) -> Dict:
        """
        Scan a target for vulnerabilities.

        Args:
            target: Target URL or host
            templates: List of template categories to use
            rate: Requests per second
            timeout: Scan timeout in seconds
        """
        results = {
            "target": target,
            "vulnerabilities": [],
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "total": 0,
        }

        try:
            cmd = [
                "nuclei",
                "-u", target,
                "-json",
                "-silent",
                "-nc",
            ]

            if templates:
                template_paths = ",".join(templates)
                cmd.extend(["-t", template_paths])

            cmd.extend(["-rate", str(rate)])

            if self.templates_dir.exists():
                cmd.extend(["-nt", str(self.templates_dir)])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode in [0, 1]:
                for line in result.stdout.splitlines():
                    if line.strip():
                        try:
                            vuln = json.loads(line)
                            severity = vuln.get("info", {}).get("severity", "info").lower()
                            if severity in self.severity_filter:
                                results["vulnerabilities"].append({
                                    "name": vuln.get("info", {}).get("name", ""),
                                    "severity": severity,
                                    "matched_at": vuln.get("matched-at", ""),
                                    "description": vuln.get("info", {}).get("description", "")[:200],
                                    "reference": vuln.get("info", {}).get("reference", []),
                                })
                                results["by_severity"][severity] = results["by_severity"].get(severity, 0) + 1
                        except json.JSONDecodeError:
                            pass
        except FileNotFoundError:
            logger.warning("nuclei not found")
        except subprocess.TimeoutExpired:
            logger.warning(f"Nuclei scan timed out for {target}")
        except Exception as e:
            logger.error(f"Error scanning {target}: {e}")

        results["total"] = sum(results["by_severity"].values())
        return results

    async def scan_batch(
        self,
        targets: List[str],
        rate: int = 150,
    ) -> Dict:
        """Scan multiple targets."""
        all_results = {
            "targets": len(targets),
            "vulnerabilities": [],
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "total": 0,
        }

        for target in targets:
            result = await self.scan(target, rate=rate)
            all_results["vulnerabilities"].extend(result["vulnerabilities"])

            for severity, count in result["by_severity"].items():
                all_results["by_severity"][severity] += count

        all_results["total"] = sum(all_results["by_severity"].values())
        return all_results


class TemplateManager:
    """Manage custom Nuclei templates."""

    def __init__(self, templates_dir: str = "./nuclei-templates"):
        self.templates_dir = Path(templates_dir)

    def create_git_config_template(self) -> Dict:
        """Create template for .git/config detection."""
        return {
            "id": "git-config-exposure",
            "info": {
                "name": "Git Config Exposure",
                "author": "tbhm",
                "severity": "high",
                "description": "Git configuration file detected",
            },
            "requests": [{
                "method": "GET",
                "path": ["/.git/config"],
                "matchers": [{
                    "condition": "and",
                    "matchers": [{
                        "type": "word",
                        "words": ["[core]"],
                    }],
                }],
            }],
        }

    def create_swagger_template(self) -> Dict:
        """Create template for Swagger UI detection."""
        return {
            "id": "swagger-ui-exposure",
            "info": {
                "name": "Swagger UI Exposure",
                "author": "tbhm",
                "severity": "medium",
                "description": "Swagger UI endpoint detected",
            },
            "requests": [{
                "method": "GET",
                "path": ["/swagger-ui/", "/swagger-ui", "/api/docs", "/api/swagger"],
                "matchers": [{
                    "condition": "or",
                    "matchers": [{
                        "type": "word",
                        "words": ["swagger", "OpenAPI"],
                    }],
                }],
            }],
        }

    def create_env_template(self) -> Dict:
        """Create template for .env file detection."""
        return {
            "id": "env-file-exposure",
            "info": {
                "name": "Env File Exposure",
                "author": "tbhm",
                "severity": "critical",
                "description": "Environment file detected with sensitive data",
            },
            "requests": [{
                "method": "GET",
                "path": ["/.env", "/.env.local", "/.env.prod"],
                "matchers": [{
                    "condition": "and",
                    "matchers": [{
                        "type": "regex",
                        "pattern": "(API_KEY|TOKEN|SECRET|PASSWORD)",
                    }],
                }],
            }],
        }


async def run_vuln_scan(
    target_id: str,
    targets: List[str],
    templates: Optional[List[str]] = None,
    rate: int = 150,
) -> dict:
    """Run vulnerability scan on targets."""
    scanner = NucleiScanner()

    result = await scanner.scan_batch(targets, rate)

    result["target_id"] = target_id
    return result