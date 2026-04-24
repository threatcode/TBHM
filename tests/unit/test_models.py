"""Unit tests for database models."""

import pytest
import uuid
from datetime import datetime

from tbhm.db.models import Scan, ScanStatus, Target


class TestTarget:
    """Test Target model."""

    def test_target_creation(self):
        """Test target can be created."""
        target = Target(
            name="Test Target",
            domain="example.com",
            company="Test Company",
        )
        assert target.name == "Test Target"
        assert target.domain == "example.com"
        assert target.company == "Test Company"

    def test_target_default_values(self):
        """Test target has default values."""
        target = Target(
            name="Test Target",
            domain="example.com",
        )
        assert target.id is None
        assert target.created_at is None
        assert target.updated_at is None


class TestScan:
    """Test Scan model."""

    def test_scan_creation(self):
        """Test scan can be created."""
        target_id = uuid.uuid4()
        scan = Scan(
            target_id=target_id,
            scan_type="subdomain",
        )
        assert scan.target_id == target_id
        assert scan.scan_type == "subdomain"
        assert scan.status == ScanStatus.PENDING

    def test_scan_status_enum(self):
        """Test scan status enum values."""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.CANCELLED.value == "cancelled"

    def test_scan_with_results(self):
        """Test scan can store results."""
        target_id = uuid.uuid4()
        scan = Scan(
            target_id=target_id,
            scan_type="vuln_scan",
            results='{"vulnerabilities": []}',
        )
        assert scan.results is not None

    def test_scan_with_error(self):
        """Test scan can store error message."""
        target_id = uuid.uuid4()
        scan = Scan(
            target_id=target_id,
            scan_type="vuln_scan",
            error_message="Connection timeout",
        )
        assert scan.error_message == "Connection timeout"