"""
Tool verification utilities for CLI tools required by TBHM.
"""

import asyncio
import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """Tool information."""
    name: str
    installed: bool
    version: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None


class ToolVerifier:
    """Verify presence and accessibility of required CLI tools."""

    REQUIRED_TOOLS = [
        "nuclei",
        "ffuf",
        "subfinder",
        "assetfinder",
        "curl",
        "wget",
        "git",
    ]

    OPTIONAL_TOOLS = [
        "naabu",
        "gowitness",
        "subjs",
        "gau",
        "waybackurls",
        "amass",
        "dirsearch",
        "sqlmap",
    ]

    def __init__(self):
        self.tools: List[ToolInfo] = []

    def check_tool(self, tool_name: str) -> ToolInfo:
        """Check if a tool is available."""
        path = shutil.which(tool_name)
        
        if path:
            try:
                result = subprocess.run(
                    [tool_name, "-version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                version = result.stdout.strip() or result.stderr.strip() or "unknown"
                if len(version) > 100:
                    version = version[:100]
                return ToolInfo(
                    name=tool_name,
                    installed=True,
                    version=version,
                    path=path,
                )
            except subprocess.TimeoutExpired:
                return ToolInfo(
                    name=tool_name,
                    installed=True,
                    path=path,
                    error="timeout checking version",
                )
            except Exception as e:
                return ToolInfo(
                    name=tool_name,
                    installed=True,
                    path=path,
                    error=str(e),
                )
        else:
            return ToolInfo(
                name=tool_name,
                installed=False,
                error="tool not found in PATH",
            )

    def verify_required(self) -> List[ToolInfo]:
        """Verify all required tools."""
        self.tools = []
        for tool in self.REQUIRED_TOOLS:
            tool_info = self.check_tool(tool)
            self.tools.append(tool_info)
            if not tool_info.installed:
                logger.warning(f"Required tool '{tool}' not found")
        return self.tools

    def verify_optional(self) -> List[ToolInfo]:
        """Verify all optional tools."""
        self.tools = []
        for tool in self.OPTIONAL_TOOLS:
            tool_info = self.check_tool(tool)
            self.tools.append(tool_info)
            if not tool_info.installed:
                logger.info(f"Optional tool '{tool}' not found")
        return self.tools

    def verify_all(self) -> List[ToolInfo]:
        """Verify all tools."""
        self.tools = []
        for tool in self.REQUIRED_TOOLS + self.OPTIONAL_TOOLS:
            tool_info = self.check_tool(tool)
            self.tools.append(tool_info)
        return self.tools

    def get_missing_required(self) -> List[str]:
        """Get list of missing required tools."""
        self.verify_required()
        return [t.name for t in self.tools if not t.installed]

    def is_ready(self) -> bool:
        """Check if all required tools are available."""
        return len(self.get_missing_required()) == 0


async def verify_tools_async() -> List[ToolInfo]:
    """Async wrapper for tool verification."""
    verifier = ToolVerifier()
    
    def run_verification():
        return verifier.verify_all()
    
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, run_verification)


def verify_tools() -> List[ToolInfo]:
    """Synchronous tool verification."""
    verifier = ToolVerifier()
    return verifier.verify_all()