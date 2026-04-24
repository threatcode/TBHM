"""
Tool wrapper with auto-detection and graceful fallback.
"""

import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Result of a tool execution."""
    success: bool
    output: str
    error: Optional[str] = None
    returncode: int = 0


class ToolWrapper:
    """Wrapper for CLI tools with auto-detection and fallback."""
    
    def __init__(self, name: str):
        self.name = name
        self.path = shutil.which(name)
        self.available = self.path is not None
    
    def require(self) -> bool:
        """Check if tool is available, logging warning if not."""
        if not self.available:
            logger.warning(f"Tool '{self.name}' not found in PATH")
            return False
        return True
    
    def run(
        self,
        args: List[str],
        timeout: int = 60,
        input_data: Optional[str] = None,
    ) -> ToolResult:
        """Run the tool with given arguments."""
        if not self.require():
            return ToolResult(
                success=False,
                output="",
                error=f"Tool '{self.name}' not available",
            )
        
        try:
            result = subprocess.run(
                [self.name] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_data,
            )
            return ToolResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr if result.returncode != 0 else None,
                returncode=result.returncode,
            )
        except subprocess.TimeoutExpired:
            logger.error(f"Tool '{self.name}' timed out after {timeout}s")
            return ToolResult(
                success=False,
                output="",
                error=f"Timeout after {timeout}s",
            )
        except Exception as e:
            logger.error(f"Error running '{self.name}': {e}")
            return ToolResult(
                success=False,
                output="",
                error=str(e),
            )


class SubprocessRunner:
    """Safe subprocess runner with tool detection."""
    
    TOOL_MAP = {
        "nuclei": ["nuclei", "-version"],
        "ffuf": ["ffuf", "-V"],
        "subfinder": ["subfinder", "-version"],
        "assetfinder": ["assetfinder", "--version"],
        "naabu": ["naabu", "-version"],
        "gowitness": ["gowitness", "--version"],
        "subjs": ["subjs", "-version"],
        "gau": ["gau", "--version"],
        "waybackurls": ["waybackurls", "-version"],
        "amass": ["amass", "enum", "-version"],
        "dirsearch": ["dirsearch", "--version"],
        "sqlmap": ["sqlmap", "--version"],
        "nmap": ["nmap", "--version"],
        "curl": ["curl", "--version"],
        "wafw00f": ["wafw00f", "--version"],
    }
    
    def __init__(self):
        self.available_tools: dict = {}
        self._detect_tools()
    
    def _detect_tools(self):
        """Detect available tools."""
        for tool_name, version_cmd in self.TOOL_MAP.items():
            tool = shutil.which(tool_name)
            if tool:
                self.available_tools[tool_name] = {
                    "path": tool,
                    "available": True,
                }
            else:
                self.available_tools[tool_name] = {
                    "path": None,
                    "available": False,
                }
    
    def is_available(self, tool_name: str) -> bool:
        """Check if a tool is available."""
        return self.available_tools.get(tool_name, {}).get("available", False)
    
    def get_missing(self, tools: List[str]) -> List[str]:
        """Get list of missing tools from required list."""
        return [t for t in tools if not self.is_available(t)]
    
    def run_safe(
        self,
        tool: str,
        args: List[str],
        required: bool = False,
        timeout: int = 60,
    ) -> ToolResult:
        """
        Run a tool safely.
        
        Args:
            tool: Tool name
            args: Arguments to pass to the tool
            required: If True, log error when tool is missing
            timeout: Timeout in seconds
        
        Returns:
            ToolResult with execution details
        """
        if not self.is_available(tool):
            if required:
                logger.error(f"Required tool '{tool}' not found")
            return ToolResult(
                success=False,
                output="",
                error=f"Tool '{tool}' not found" if required else None,
            )
        
        try:
            result = subprocess.run(
                [tool] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return ToolResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr if result.returncode != 0 else None,
                returncode=result.returncode,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                output="",
                error=f"Timeout after {timeout}s",
            )
        except FileNotFoundError:
            return ToolResult(
                success=False,
                output="",
                error=f"Tool '{tool}' not found",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e),
            )
    
    def get_status(self) -> dict:
        """Get status of all tracked tools."""
        return self.available_tools.copy()


subprocess_runner = SubprocessRunner()


def run_if_available(tool: str, args: List[str], timeout: int = 60) -> ToolResult:
    """Run a tool only if it's available."""
    return subprocess_runner.run_safe(tool, args, required=False, timeout=timeout)


def run_required(tool: str, args: List[str], timeout: int = 60) -> ToolResult:
    """Run a tool, returning error if not available."""
    return subprocess_runner.run_safe(tool, args, required=True, timeout=timeout)