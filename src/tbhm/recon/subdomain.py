"""
Subdomain enumeration module.
"""

import asyncio
import json
import logging
import subprocess
from typing import List, Optional

logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """Subdomain enumeration using multiple data sources."""

    def __init__(self):
        self.tools = ["subfinder", "assetfinder", "findomain", "curl"]

    async def enumerate(
        self,
        domain: str,
        sources: Optional[List[str]] = None,
        recursive: bool = True,
    ) -> List[str]:
        """
        Enumerate subdomains for a given domain.

        Args:
            domain: Target domain
            sources: Specific sources to use (default: all)
            recursive: Enable recursive subdomain enumeration
        """
        subdomains = set()

        if sources is None:
            sources = ["subfinder", "assetfinder"]

        for source in sources:
            try:
                result = await self._run_tool(source, domain)
                subdomains.update(result)
            except Exception as e:
                logger.warning(f"Failed to run {source}: {e}")

        if recursive:
            for sub in list(subdomains):
                if sub != domain:
                    recursive_subs = await self._recursive_enumerate(sub)
                    subdomains.update(recursive_subs)

        return sorted(list(subdomains))

    async def _run_tool(self, tool: str, domain: str) -> List[str]:
        """Run a subdomain enumeration tool."""
        cmd_map = {
            "subfinder": ["subfinder", "-d", domain, "-silent"],
            "assetfinder": ["assetfinder", "--subs-only", domain],
            "findomain": ["findomain", "-t", domain, "-q"],
            "github-subdomains": ["github-subdomains", "-d", domain],
        }

        cmd = cmd_map.get(tool)
        if not cmd:
            return []

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                return [
                    line.strip()
                    for line in result.stdout.splitlines()
                    if line.strip()
                ]
        except FileNotFoundError:
            logger.warning(f"Tool {tool} not found - skipping")
        except subprocess.TimeoutExpired:
            logger.warning(f"Tool {tool} timed out")
        except Exception as e:
            logger.error(f"Error running {tool}: {e}")

        return []

    async def _recursive_enumerate(self, domain: str) -> List[str]:
        """Recursively enumerate subdomains."""
        return await self.enumerate(domain, sources=["subfinder"], recursive=False)

    async def validate_resolving(
        self,
        subdomains: List[str],
    ) -> dict[str, List[str]]:
        """
        Validate which subdomains resolve to IP addresses.

        Returns:
            Dict mapping subdomains to their IP addresses
        """
        resolving = {}

        for subdomain in subdomains:
            try:
                result = await asyncio.wait_for(
                    asyncio.getaddrinfo(subdomain, None),
                    timeout=5,
                )
                ips = list(set([r[4][0] for r in result]))
                if ips:
                    resolving[subdomain] = ips
            except Exception:
                pass

        return resolving


async def run_subdomain_enum(
    target_id: str,
    domain: str,
    sources: Optional[List[str]] = None,
) -> dict:
    """Run subdomain enumeration and return results."""
    enumerator = SubdomainEnumerator()
    subdomains = await enumerator.enumerate(domain, sources)

    resolving = await enumerator.validate_resolving(subdomains)

    return {
        "target_id": target_id,
        "domain": domain,
        "total_found": len(subdomains),
        "resolving_count": len(resolving),
        "subdomains": list(subdomains),
        "resolving": resolving,
    }