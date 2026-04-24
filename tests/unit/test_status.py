"""Unit tests for TBHM application."""

from tbhm.db.models import ScanStatus


class TestScanStatus:
    """Test ScanStatus enum values."""

    def test_status_values(self):
        """Test all status enum values."""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.CANCELLED.value == "cancelled"

    def test_status_transitions(self):
        """Test valid status transitions."""
        valid_transitions = {
            ScanStatus.PENDING: [ScanStatus.RUNNING, ScanStatus.CANCELLED],
            ScanStatus.RUNNING: [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED],
            ScanStatus.COMPLETED: [],
            ScanStatus.FAILED: [],
            ScanStatus.CANCELLED: [],
        }
        
        assert ScanStatus.PENDING in valid_transitions[ScanStatus.PENDING]
        assert ScanStatus.COMPLETED not in valid_transitions[ScanStatus.COMPLETED]