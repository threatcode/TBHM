"""
IP range and ASN discovery module.
"""

import logging
import subprocess
from typing import List, Optional

logger = logging.getLogger(__name__)


class IPEnumerator:
    """IP range and ASN discovery."""

    async def enumerate_asn(
        self,
        company_name: str,
    ) -> List[dict]:
        """
        Find ASN records for a company.
        """
        results = []

        try:
            result = subprocess.run(
                ["asnlookup", company_name],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip().startswith("AS"):
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            results.append({
                                "asn": parts[0],
                                "cidr": " ".join(parts[1:]),
                            })
        except FileNotFoundError:
            logger.warning("asnlookup not found")
        except Exception as e:
            logger.error(f"Error running asnlookup: {e}")

        return results

    async def enumerate_whois(
        self,
        domain: str,
    ) -> dict:
        """
        Get WHOIS data for a domain.
        """
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return self._parse_whois(result.stdout)
        except FileNotFoundError:
            logger.warning("whois command not found")
        except Exception as e:
            logger.error(f"Error running whois: {e}")

        return {}

    def _parse_whois(self, whois_data: str) -> dict:
        """Parse WHOIS text output."""
        parsed = {}
        current_key = None

        for line in whois_data.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()

                if key in ["country", "state", "city", "org", " registrar"]:
                    parsed[key] = value

        return parsed

    async def reverse_dns(
        self,
        ip_range: str,
    ) -> List[str]:
        """
        Perform reverse DNS lookup for an IP range.
        """
        try:
            result = subprocess.run(
                ["dig", "-x", ip_range, "+short"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return [
                    line.strip()
                    for line in result.stdout.splitlines()
                    if line.strip()
                ]
        except FileNotFoundError:
            logger.warning("dig not found")
        except Exception as e:
            logger.error(f"Error running dig: {e}")

        return []

    async def get_org_ips(
        self,
        org: str,
    ) -> List[dict]:
        """
        Get IP ranges for an organization using BGP data.
        """
        results = []

        try:
            result = subprocess.run(
                ["asnmaster", "-o", org],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2 and "/" in parts[0]:
                        results.append({
                            "cidr": parts[0],
                            "description": " ".join(parts[1:]),
                        })
        except FileNotFoundError:
            logger.warning("asnmaster not found")
        except Exception as e:
            logger.error(f"Error running asnmaster: {e}")

        return results


async def run_ip_discovery(
    target_id: str,
    domain: str,
    company: Optional[str] = None,
) -> dict:
    """Run IP discovery and return results."""
    enumerator = IPEnumerator()

    asn_results = []
    if company:
        asn_results = await enumerator.enumerate_asn(company)

    whois_data = await enumerator.enumerate_whois(domain)

    return {
        "target_id": target_id,
        "domain": domain,
        "asn_records": asn_results,
        "whois_data": whois_data,
    }