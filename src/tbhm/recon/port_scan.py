"""
Port scanning and service discovery module.
"""

import json
import logging
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_PORTS = "20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443,27017"


class PortScanner:
    """Port scanning using naabu."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    async def scan(
        self,
        host: str,
        ports: Optional[str] = None,
        rate: int = 1000,
    ) -> List[Dict]:
        """
        Scan ports on a single host.

        Args:
            host: Target IP or hostname
            ports: Comma-separated port list or range
            rate: Packets per second
        """
        if ports is None:
            ports = DEFAULT_PORTS

        results = []

        try:
            cmd = [
                "naabu",
                "-host", host,
                "-ports", ports,
                "-rate", str(rate),
                "-json",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2,
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip():
                        try:
                            data = json.loads(line)
                            results.append(data)
                        except json.JSONDecodeError:
                            pass
        except FileNotFoundError:
            logger.warning("naabu not found")
        except subprocess.TimeoutExpired:
            logger.warning(f"Scan timed out for {host}")
        except Exception as e:
            logger.error(f"Error scanning {host}: {e}")

        return results

    async def scan_network(
        self,
        cidr: str,
        ports: Optional[str] = None,
        rate: int = 1000,
    ) -> List[Dict]:
        """Scan an entire network range."""
        if ports is None:
            ports = DEFAULT_PORTS

        results = []

        try:
            cmd = [
                "naabu",
                "-host", cidr,
                "-ports", ports,
                "-rate", str(rate),
                "-json",
                "-scan-all-ports",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip():
                        try:
                            data = json.loads(line)
                            results.append(data)
                        except json.JSONDecodeError:
                            pass
        except FileNotFoundError:
            logger.warning("naabu not found")
        except subprocess.TimeoutExpired:
            logger.warning(f"Scan timed out for {cidr}")
        except Exception as e:
            logger.error(f"Error scanning {cidr}: {e}")

        return results


class ServiceFingerprinter:
    """Service fingerprinting and identification."""

    def __init__(self):
        self.common_services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            1521: "oracle",
            1723: "pptp",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb",
        }

    def identify_service(self, port: int, banner: Optional[str] = None) -> str:
        """Identify service from port and banner."""
        if banner:
            banner_lower = banner.lower()
            if "ssh" in banner_lower:
                return "ssh"
            if "ftp" in banner_lower:
                return "ftp"
            if "mysql" in banner_lower:
                return "mysql"
            if "redis" in banner_lower:
                return "redis"
            if "postgresql" in banner_lower:
                return "postgresql"
            if "mongodb" in banner_lower:
                return "mongodb"

        return self.common_services.get(port, "unknown")

    def is_rdp(self, port: int, banner: Optional[str] = None) -> bool:
        """Check if service is RDP."""
        if port == 3389:
            return True
        if banner and "rdp" in banner.lower():
            return True
        return False

    def is_smb(self, port: int, banner: Optional[str] = None) -> bool:
        """Check if service is SMB."""
        if port in [139, 445]:
            return True
        if banner and "samba" in banner.lower():
            return True
        return False

    def is_ssh(self, port: int, banner: Optional[str] = None) -> bool:
        """Check if service is SSH."""
        if port == 22:
            return True
        if banner and "ssh" in banner.lower():
            return True
        return False

    def is_http(self, port: int, banner: Optional[str] = None) -> bool:
        """Check if service is HTTP-based."""
        if port in [80, 443, 8080, 8443]:
            return True
        if banner:
            banner_lower = banner.lower()
            if "http" in banner_lower or "nginx" in banner_lower or "apache" in banner_lower:
                return True
        return False


async def run_port_scan(
    target_id: str,
    hosts: List[str],
    ports: Optional[str] = None,
    rate: int = 1000,
) -> dict:
    """Run port scan on multiple hosts."""
    scanner = PortScanner()
    fingerprinter = ServiceFingerprinter()

    all_results = []
    services_found = []

    for host in hosts:
        results = await scanner.scan(host, ports, rate)
        all_results.extend(results)

        for result in results:
            port = result.get("port", 0)
            banner = result.get("banner", "")
            service = fingerprinter.identify_service(port, banner)

            services_found.append({
                "host": host,
                "port": port,
                "service": service,
                "banner": banner,
                "is_rdp": fingerprinter.is_rdp(port, banner),
                "is_smb": fingerprinter.is_smb(port, banner),
                "is_ssh": fingerprinter.is_ssh(port, banner),
                "is_http": fingerprinter.is_http(port, banner),
            })

    return {
        "target_id": target_id,
        "total_hosts": len(hosts),
        "open_ports": len(all_results),
        "services": services_found,
    }