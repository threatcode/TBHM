"""
Web fingerprinting and technology detection module.
"""

import logging
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class WebFingerprinter:
    """Web technology fingerprinting using httpx."""

    def __init__(self, follow_redirects: bool = True, timeout: int = 30):
        self.follow_redirects = follow_redirects
        self.timeout = timeout

    async def fingerprint(
        self,
        url: str,
    ) -> dict:
        """
        Fingerprint a single URL.
        """
        result = {
            "url": url,
            "status_code": None,
            "content_length": None,
            "content_type": None,
            "server": None,
            "technologies": [],
            "title": None,
            "favicon_hash": None,
            "ips": [],
            "cdn": None,
        }

        try:
            cmd = [
                "httpx",
                "-u", url,
                "-json",
                "-title",
                "-server",
                "-tech-detect",
                "-favicon",
                "-follow-redirects" if self.follow_redirects else "",
            ]
            cmd = [c for c in cmd if c]

            proc = await subprocess.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                import json
                try:
                    data = json.loads(stdout.decode())
                    result.update(data)
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.error(f"Error fingerprinting {url}: {e}")

        return result

    async def fingerprint_batch(
        self,
        urls: List[str],
        threads: int = 50,
    ) -> List[dict]:
        """
        Fingerprint multiple URLs concurrently.
        """
        results = []

        try:
            cmd = [
                "httpx",
                "-l", ",".join(urls),
                "-json",
                "-title",
                "-server",
                "-tech-detect",
                "-threads", str(threads),
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout * len(urls) // threads + 60,
            )

            if result.returncode == 0:
                import json
                for line in result.stdout.splitlines():
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.error(f"Error batch fingerprinting: {e}")

        return results

    def extract_technologies(self, fingerprint_data: dict) -> List[str]:
        """Extract technology list from fingerprint data."""
        techs = []
        if "technologies" in fingerprint_data:
            for tech in fingerprint_data["technologies"]:
                if isinstance(tech, dict):
                    techs.append(tech.get("name", ""))
                else:
                    techs.append(str(tech))
        return [t for t in techs if t]

    def detect_cdn(self, fingerprint_data: dict) -> Optional[str]:
        """Detect CDN from fingerprint data."""
        cdn_patterns = {
            "cloudflare": ["cloudflare", "cf-ray"],
            "akamai": ["akamai", "akamai-ghost"],
            "fastly": ["fastly", "x-served-by"],
            "aws_cloudfront": ["cloudfront"],
            "azure": ["x-azure-fx", "azure"],
            "google_cloud": ["google", "x-goog-hdr"],
        }

        headers = fingerprint_data.get("header", {}).get("raw", "")

        for cdn, patterns in cdn_patterns.items():
            for pattern in patterns:
                if pattern.lower() in headers.lower():
                    return cdn

        return None


async def run_fingerprint(
    target_id: str,
    subdomains: List[str],
) -> dict:
    """Run web fingerprinting on subdomains."""
    fingerprinter = WebFingerprinter()

    urls = [f"http://{sub}" for sub in subdomains]
    urls.extend([f"https://{sub}" for sub in subdomains])

    results = await fingerprinter.fingerprint_batch(urls)

    tech_summary = {}
    live_hosts = []

    for result in results:
        if result.get("status_code"):
            host = result.get("host") or result.get("url", "").split("//")[1].split("/")[0]
            live_hosts.append(host)

            for tech in fingerprinter.extract_technologies(result):
                tech_summary[tech] = tech_summary.get(tech, 0) + 1

    return {
        "target_id": target_id,
        "total_scanned": len(urls),
        "live_hosts": live_hosts,
        "live_count": len(live_hosts),
        "technologies": tech_summary,
        "fingerprint_results": results,
    }