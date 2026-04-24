"""
JavaScript extraction and analysis module.
"""

import json
import logging
import re
import subprocess
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class JavaScriptExtractor:
    """Extract JavaScript files from web archives and live sources."""

    def __init__(self):
        self.js_extensions = [".js", ".jsx", ".mjs", ".ts", ".tsx"]

    async def extract_from_wayback(
        self,
        domain: str,
    ) -> List[str]:
        """
        Extract JS files from Wayback Machine.
        """
        results = []

        try:
            cmd = ["waybackurls", domain]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if any(ext in line.lower() for ext in self.js_extensions):
                        results.append(line.strip())
        except FileNotFoundError:
            logger.warning("waybackurls not found")
        except Exception as e:
            logger.error(f"Error extracting from wayback: {e}")

        return list(set(results))

    async def extract_from_gau(
        self,
        domain: str,
    ) -> List[str]:
        """
        Extract JS files using GAU (Get All URLs).
        """
        results = []

        try:
            cmd = ["gau", "--subs", domain]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if any(ext in line.lower() for ext in self.js_extensions):
                        results.append(line.strip())
        except FileNotFoundError:
            logger.warning("gau not found")
        except Exception as e:
            logger.error(f"Error extracting from gau: {e}")

        return list(set(results))

    async def extract_from_subjs(
        self,
        domain: str,
    ) -> List[str]:
        """
        Extract JS files using subjs.
        """
        results = []

        try:
            cmd = ["subjs", domain]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip():
                        results.append(line.strip())
        except FileNotFoundError:
            logger.warning("subjs not found")
        except Exception as e:
            logger.error(f"Error extracting from subjs: {e}")

        return list(set(results))


class EndpointFinder:
    """Find API endpoints in JavaScript files."""

    def __init__(self):
        self.endpoint_patterns = [
            r"['\"]((?:api|v[0-9]+|rest|graphql)/[a-zA-Z0-9/_-]+)['\"]",
            r"endpoint\s*:\s*['\"]([^'\"]+)['\"]",
            r"url\s*:\s*['\"]([^'\"]+)['\"]",
            r"href\s*=\s*['\"]([^'\"]+)['\"]",
            r"action\s*=\s*['\"]([^'\"]+)['\"]",
            r"location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"fetch\s*\(\s*['\"]([^'\"]+)['\"]",
            r"axios[.]\w+\s*\(\s*['\"]([^'\"]+)['\"]",
            r"\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['\"]([^'\"]+)['\"]",
            r"\$http\.\w+\s*\(\s*['\"]([^'\"]+)['\"]",
        ]

    def find_endpoints(self, js_content: str) -> List[Dict]:
        """Find endpoints in JavaScript content."""
        endpoints = []

        for pattern in self.endpoint_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                endpoints.append({
                    "endpoint": match.group(1),
                    "pattern": pattern[:50],
                })

        return endpoints

    def find_ajax_calls(self, js_content: str) -> List[Dict]:
        """Find AJAX/fetch calls."""
        ajax_calls = []

        fetch_pattern = r"fetch\s*\(\s*['\"]([^'\"]+)['\"]"
        for match in re.finditer(fetch_pattern, js_content, re.IGNORECASE):
            ajax_calls.append({
                "type": "fetch",
                "url": match.group(1),
            })

        axios_pattern = r"axios[.](get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]"
        for match in re.finditer(axios_pattern, js_content, re.IGNORECASE):
            ajax_calls.append({
                "type": "axios",
                "method": match.group(1),
                "url": match.group(2),
            })

        return ajax_calls


class SecretFinder:
    """Find API keys and secrets in JavaScript."""

    def __init__(self):
        self.secret_patterns = {
            "AWS_ACCESS_KEY": (r"AKIA[0-9A-Z]{16}", "aws"),
            "AWS_SECRET_KEY": (r"[A-Za-z0-9/+=]{40}", "aws"),
            "GOOGLE_API": (r"AIza[0-9A-Za-z-_]{35}", "google"),
            "GOOGLE_OAUTH": (r"ya29\.[0-9A-Za-z-_]+", "google"),
            "FACEBOOK_TOKEN": (r"EAACEdEose0cBA[0-9A-Za-z]+", "facebook"),
            "TWITTER_KEY": (r"[a-zA-Z0-9]{25,}\.[a-zA-Z0-9]{15,}", "twitter"),
            "GITHUB_TOKEN": (r"ghp_[a-zA-Z0-9]{36}", "github"),
            "GITHUB_OAUTH": (r"gho_[a-zA-Z0-9]{36}", "github"),
            "NPM_TOKEN": (r"npm_[a-zA-Z0-9]{36}", "npm"),
            "SLACK_TOKEN": (r"xox[baprs]-[0-9a-zA-Z-]+", "slack"),
            "STRIPE_KEY": (r"sk_live_[0-9a-zA-Z]{24,}", "stripe"),
            "PRIVATE_KEY": (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key"),
            "JWT": (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "jwt"),
            "API_KEY": (r"api[_-]?key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]", "api_key"),
            "Bearer_TOKEN": (r"Bearer [a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "bearer"),
        }

    def find_secrets(self, js_content: str) -> List[Dict]:
        """Find secrets in JavaScript content."""
        findings = []

        for secret_type, (pattern, service) in self.secret_patterns.items():
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": secret_type,
                    "service": service,
                    "value": match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0),
                    "location": f"line unknown",
                })

        return findings

    def find_hardcoded_urls(self, js_content: str) -> List[str]:
        """Find hardcoded URLs."""
        urls = []
        url_pattern = r"['\"]((?:https?)?://[a-zA-Z0-9.-]+/[^\"']+)['\"]"
        matches = re.finditer(url_pattern, js_content)
        for match in matches:
            url = match.group(1)
            if not url.startswith("data:"):
                urls.append(url)
        return list(set(urls))


async def run_js_extraction(
    target_id: str,
    domain: str,
) -> dict:
    """Run JavaScript extraction."""
    js_extractor = JavaScriptExtractor()
    endpoint_finder = EndpointFinder()
    secret_finder = SecretFinder()

    all_js_files = []

    all_js_files.extend(await js_extractor.extract_from_wayback(domain))
    all_js_files.extend(await js_extractor.extract_from_gau(domain))
    all_js_files = list(set(all_js_files))

    endpoints = []
    secrets = []
    hardcoded_urls = []

    for js_url in all_js_files[:50]:
        try:
            result = subprocess.run(
                ["curl", "-s", js_url],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                js_content = result.text
                endpoints.extend(endpoint_finder.find_endpoints(js_content))
                secrets.extend(secret_finder.find_secrets(js_content))
                hardcoded_urls.extend(secret_finder.find_hardcoded_urls(js_content))
        except Exception:
            pass

    return {
        "target_id": target_id,
        "domain": domain,
        "js_files_count": len(all_js_files),
        "js_files": all_js_files[:100],
        "endpoints": endpoints[:50],
        "secrets": secrets[:20],
        "hardcoded_urls": hardcoded_urls[:20],
    }