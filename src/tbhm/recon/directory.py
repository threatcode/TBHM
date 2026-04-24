"""
Directory fuzzing and content discovery module.
"""

import json
import logging
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_WORDLISTS = {
    "big": "/usr/share/wordlists/dirb/big.txt",
    "small": "/usr/share/wordlists/dirb/small.txt",
    "common": "/usr/share/wordlists/ffuf/wordlist.txt",
}


class DirectoryFuzzer:
    """Directory and file fuzzing using ffuf."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout

    async def fuzz(
        self,
        url: str,
        wordlist: Optional[str] = None,
        threads: int = 40,
        extensions: Optional[List[str]] = None,
        recursive: bool = False,
    ) -> Dict:
        """
        Fuzz directories on a target URL.

        Args:
            url: Target URL with FUZZ placeholder
            wordlist: Path to wordlist file
            threads: Number of concurrent threads
            extensions: File extensions to check (e.g., ["php", "html"])
            recursive: Enable recursive fuzzing
        """
        results = {
            "url": url,
            "total": 0,
            "found": [],
            "status_codes": {},
        }

        try:
            cmd = ["ffuf", "-u", url, "-mc", "200,204,301,302,307,401,403", "-json"]

            if wordlist:
                cmd.extend(["-w", wordlist])
            else:
                wordlist_path = DEFAULT_WORDLISTS.get("common", "/usr/share/wordlists/ffuf/wordlist.txt")
                cmd.extend(["-w", wordlist_path])

            cmd.extend(["-t", str(threads)])

            if extensions:
                ext = ",".join(extensions)
                cmd.extend(["-e", ext])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    results["total"] = data.get("results", 0)

                    for item in data.get("results", []):
                        results["found"].append({
                            "url": item.get("url", ""),
                            "status": item.get("status", 0),
                            "length": item.get("length", 0),
                            "words": item.get("words", 0),
                            "lines": item.get("lines", 0),
                        })

                        status = item.get("status", 0)
                        results["status_codes"][status] = results["status_codes"].get(status, 0) + 1
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            logger.warning("ffuf not found")
        except subprocess.TimeoutExpired:
            logger.warning(f"Fuzzing timed out for {url}")
        except Exception as e:
            logger.error(f"Error fuzzing {url}: {e}")

        return results

    async def fuzz_batch(
        self,
        urls: List[str],
        wordlist: Optional[str] = None,
        threads: int = 40,
    ) -> List[Dict]:
        """Fuzz multiple URLs."""
        results = []

        for url in urls:
            result = await self.fuzz(url, wordlist, threads)
            results.append(result)

        return results


class Bypass403:
    """403 bypass techniques."""

    def __init__(self):
        self.bypass_methods = [
            {"method": "GET", "path": "/"},
            {"method": "GET", "path": "//"},
            {"method": "GET", "path": "/./"},
            {"method": "GET", "path": "/%2e/"},
            {"method": "GET", "path": "/%252e/"},
            {"method": "GET", "path": "/..;/"},
            {"method": "GET", "path": "/;/"},
            {"method": "GET", "path": "/.%0d/"},
            {"method": "GET", "path": "/%00/"},
            {"method": "GET", "path": "/?q=..."},
            {"method": "GET", "path": "/%23"},
            {"method": "GET", "path": "/"},
            {"method": "GET", "path": "/*"},
            {"method": "GET", "path": "/*/"},
            {"method": "GET", "path": "/.git/"},
            {"method": "HEAD", "path": "/"},
            {"method": "POST", "path": "/"},
            {"method": "PUT", "path": "/"},
            {"method": "PATCH", "path": "/"},
            {"method": "DELETE", "path": "/"},
        ]
        self.bypass_headers = {
            "X-Original-URL": "/",
            "X-Rewrite-URL": "/",
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Host": "localhost",
            "X-Host": "localhost",
            "X-IP": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "Client-IP": "127.0.0.1",
            "True-Client-IP": "127.0.0.1",
            "Forwarded-For": "127.0.0.1",
            "Forwarded": "for=127.0.0.1",
            "CF-Connecting-IP": "127.0.0.1",
            "X-Cluster-Client-IP": "127.0.0.1",
            "WL-Proxy-Client-IP": "127.0.0.1",
            "Proxy-Client-IP": "127.0.0.1",
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Referer": "http://localhost",
        }

    def generate_bypass_requests(self, path: str) -> List[Dict]:
        """Generate bypass requests for a path."""
        requests = []

        for header_name, header_value in self.bypass_headers.items():
            requests.append({
                "method": "GET",
                "path": path,
                "headers": {header_name: header_value},
            })

        return requests


async def run_directory_fuzz(
    target_id: str,
    url: str,
    wordlist: Optional[str] = None,
    extensions: Optional[List[str]] = None,
    threads: int = 40,
) -> dict:
    """Run directory fuzzing on a target."""
    fuzzer = DirectoryFuzzer()

    result = await fuzzer.fuzz(url, wordlist, threads, extensions)

    result["target_id"] = target_id
    return result