"""Unit tests for tool verification."""

import pytest
from unittest.mock import patch, MagicMock

from tbhm.core.tools import ToolVerifier, ToolInfo


class TestToolVerifier:
    """Test tool verification functionality."""

    @patch("shutil.which")
    def test_check_tool_installed(self, mock_which):
        """Test checking for installed tool."""
        mock_which.return_value = "/usr/bin/curl"
        
        verifier = ToolVerifier()
        tool_info = verifier.check_tool("curl")
        
        assert tool_info.installed is True
        assert tool_info.name == "curl"

    @patch("shutil.which")
    def test_check_tool_not_installed(self, mock_which):
        """Test checking for missing tool."""
        mock_which.return_value = None
        
        verifier = ToolVerifier()
        tool_info = verifier.check_tool("nonexistent_tool")
        
        assert tool_info.installed is False
        assert tool_info.error == "tool not found in PATH"

    @patch("shutil.which")
    def test_verify_required_tools(self, mock_which):
        """Test verifying required tools."""
        mock_which.side_effect = lambda x: f"/usr/bin/{x}" if x in ["curl", "git"] else None
        
        verifier = ToolVerifier()
        tools = verifier.verify_required()
        
        assert len(tools) > 0

    @patch("shutil.which")
    def test_get_missing_required(self, mock_which):
        """Test getting missing required tools."""
        mock_which.side_effect = lambda x: f"/usr/bin/{x}" if x == "curl" else None
        
        verifier = ToolVerifier()
        missing = verifier.get_missing_required()
        
        assert "nuclei" in missing or "subfinder" in missing or "assetfinder" in missing

    @patch("shutil.which")
    def test_is_ready(self, mock_which):
        """Test readiness check when all tools present."""
        mock_which.return_value = "/usr/bin/tool"
        
        verifier = ToolVerifier()
        ready = verifier.is_ready()
        
        assert isinstance(ready, bool)


class TestToolInfo:
    """Test ToolInfo dataclass."""

    def test_tool_info_creation(self):
        """Test ToolInfo creation."""
        tool_info = ToolInfo(
            name="test_tool",
            installed=True,
            version="1.0.0",
            path="/usr/bin/test_tool",
        )
        
        assert tool_info.name == "test_tool"
        assert tool_info.installed is True
        assert tool_info.version == "1.0.0"

    def test_tool_info_not_installed(self):
        """Test ToolInfo for missing tool."""
        tool_info = ToolInfo(
            name="missing",
            installed=False,
            error="not found",
        )
        
        assert tool_info.installed is False
        assert tool_info.error == "not found"