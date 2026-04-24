"""
Screenshot and visual analysis module.
"""

import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SCREENSHOT_DIR = "./data/screenshots"


class ScreenshotCapture:
    """Screenshot capture using gowitness."""

    def __init__(self, output_dir: str = SCREENSHOT_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def capture(
        self,
        url: str,
        width: int = 1280,
        height: int = 720,
        timeout: int = 30,
    ) -> Dict:
        """
        Capture screenshot of a URL.

        Args:
            url: Target URL
            width: Browser viewport width
            height: Browser viewport height
            timeout: Capture timeout in seconds
        """
        result = {
            "url": url,
            "screenshot_path": None,
            "success": False,
            "error": None,
        }

        domain = url.split("//")[-1].split("/")[0].split(":")[0]
        output_file = self.output_dir / f"{domain}.png"

        try:
            cmd = [
                "gowitness",
                "single",
                url,
                "--screenshot-path", str(self.output_dir),
                "--fullpage",
            ]

            proc = await subprocess.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )

                if proc.returncode == 0 and output_file.exists():
                    result["screenshot_path"] = str(output_file)
                    result["success"] = True
            except asyncio.TimeoutError:
                await proc.kill()
                result["error"] = "Timeout"
        except FileNotFoundError:
            logger.warning("gowitness not found")
            result["error"] = "Tool not found"
        except Exception as e:
            logger.error(f"Error capturing {url}: {e}")
            result["error"] = str(e)

        return result

    async def capture_batch(
        self,
        urls: List[str],
        threads: int = 10,
    ) -> List[Dict]:
        """
        Capture screenshots of multiple URLs.

        Args:
            urls: List of target URLs
            threads: Number of parallel threads
        """
        results = []

        try:
            url_file = self.output_dir / "urls.txt"
            with open(url_file, "w") as f:
                f.write("\n".join(urls))

            cmd = [
                "gowitness",
                "batch",
                str(url_file),
                "--screenshot-path", str(self.output_dir),
                "--threads", str(threads),
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=len(urls) * 30 // threads + 60,
            )

            if result.returncode == 0:
                for url in urls:
                    domain = url.split("//")[-1].split("/")[0].split(":")[0]
                    screenshot_path = self.output_dir / f"{domain}.png"

                    results.append({
                        "url": url,
                        "screenshot_path": str(screenshot_path) if screenshot_path.exists() else None,
                        "success": screenshot_path.exists(),
                    })
        except FileNotFoundError:
            logger.warning("gowitness not found")
        except Exception as e:
            logger.error(f"Error batch capturing: {e}")

        return results


class VisualAnalyzer:
    """Analyze screenshots for interesting elements."""

    def __init__(self):
        self.login_patterns = [
            "login", "signin", "sign in", "password", "authenticate",
            "username", "email", "credential",
        ]
        self.admin_patterns = [
            "admin", "dashboard", "manage", "control panel",
            "settings", "configuration", "wp-admin",
        ]
        self.sensitive_patterns = [
            "api key", "secret", "token", "private",
            "credential", "access denied", "forbidden",
            "error", "exception", "stack trace",
        ]

    def analyze_image(self, screenshot_path: str) -> Dict:
        """
        Analyze a screenshot for interesting elements.
        
        Note: This requires a vision model like LLaVA.
        For now, returns basic metadata.
        """
        if not os.path.exists(screenshot_path):
            return {"success": False, "error": "File not found"}

        file_stat = os.stat(screenshot_path)

        return {
            "success": True,
            "file_size": file_stat.st_size,
            "path": screenshot_path,
            "interesting_elements": [],
            "needs_vision_analysis": True,
        }

    def detect_login_forms(self, ocr_text: str) -> bool:
        """Detect login forms from OCR text."""
        text_lower = ocr_text.lower()
        return any(pattern in text_lower for pattern in self.login_patterns)

    def detect_admin_panels(self, ocr_text: str) -> bool:
        """Detect admin panels from OCR text."""
        text_lower = ocr_text.lower()
        return any(pattern in text_lower for pattern in self.admin_patterns)

    def detect_sensitive_data(self, ocr_text: str) -> bool:
        """Detect sensitive data exposure from OCR text."""
        text_lower = ocr_text.lower()
        return any(pattern in text_lower for pattern in self.sensitive_patterns)


async def run_screenshot_capture(
    target_id: str,
    urls: List[str],
    fullpage: bool = True,
) -> dict:
    """Run screenshot capture on URLs."""
    capturer = ScreenshotCapture()
    analyzer = VisualAnalyzer()

    results = await capturer.capture_batch(urls)

    analyzed_results = []
    total_screenshots = 0
    login_forms = 0
    admin_panels = 0

    for result in results:
        if result.get("success"):
            total_screenshots += 1

            analysis = analyzer.analyze_image(result["screenshot_path"])
            analyzed_results.append({
                **result,
                "analysis": analysis,
            })

    return {
        "target_id": target_id,
        "total_urls": len(urls),
        "successful_captures": total_screenshots,
        "results": analyzed_results,
    }