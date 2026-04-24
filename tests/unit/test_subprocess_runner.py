"""Unit tests for subprocess runner."""

import pytest
from unittest.mock import patch, MagicMock

from tbhm.core.subprocess_runner import (
    ToolWrapper,
    ToolResult,
    SubprocessRunner,
    run_if_available,
    run_required,
)


class TestToolResult:
    """Test ToolResult dataclass."""

    def test_successful_result(self):
        """Test successful tool result."""
        result = ToolResult(
            success=True,
            output="output text",
            returncode=0,
        )
        assert result.success is True
        assert result.output == "output text"

    def test_failed_result(self):
        """Test failed tool result."""
        result = ToolResult(
            success=False,
            output="",
            error="Tool not found",
            returncode=127,
        )
        assert result.success is False
        assert result.error == "Tool not found"


class TestToolWrapper:
    """Test ToolWrapper class."""

    @patch("shutil.which")
    def test_tool_available(self, mock_which):
        """Test tool is detected as available."""
        mock_which.return_value = "/usr/bin/test_tool"
        
        wrapper = ToolWrapper("test_tool")
        assert wrapper.available is True
        assert wrapper.path == "/usr/bin/test_tool"

    @patch("shutil.which")
    def test_tool_not_available(self, mock_which):
        """Test tool is detected as not available."""
        mock_which.return_value = None
        
        wrapper = ToolWrapper("missing_tool")
        assert wrapper.available is False
        assert wrapper.path is None

    @patch("shutil.which")
    def test_require_returns_false(self, mock_which):
        """Test require returns False for missing tool."""
        mock_which.return_value = None
        
        wrapper = ToolWrapper("missing_tool")
        assert wrapper.require() is False


class TestSubprocessRunner:
    """Test SubprocessRunner class."""

    @patch("shutil.which")
    def test_is_available(self, mock_which):
        """Test checking if tool is available."""
        mock_which.side_effect = lambda x: f"/usr/bin/{x}" if x == "curl" else None
        
        runner = SubprocessRunner()
        assert runner.is_available("curl") is True
        assert runner.is_available("missing") is False

    @patch("shutil.which")
    def test_get_missing(self, mock_which):
        """Test getting missing tools."""
        mock_which.side_effect = lambda x: f"/usr/bin/{x}" if x == "curl" else None
        
        runner = SubprocessRunner()
        missing = runner.get_missing(["curl", "missing"])
        
        assert "missing" in missing
        assert "curl" not in missing

    def test_get_status(self):
        """Test getting tool status."""
        runner = SubprocessRunner()
        status = runner.get_status()
        
        assert isinstance(status, dict)


def test_run_if_available():
    """Test run_if_available function."""
    result = run_if_available("nonexistent_tool", ["--version"])
    assert result.success is False
    assert result.error is not None


def test_run_required():
    """Test run_required function."""
    result = run_required("nonexistent_tool", ["--version"])
    assert result.success is False