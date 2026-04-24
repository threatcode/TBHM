"""Unit tests for Pydantic schemas."""

import pytest
import uuid
from datetime import datetime
from pydantic import ValidationError

from tbhm.schemas import (
    TargetCreate,
    TargetUpdate,
    TargetResponse,
    ScanCreate,
    ScanUpdate,
    ScanResponse,
)


class TestTargetCreate:
    """Test TargetCreate schema."""

    def test_valid_target_create(self):
        """Test creating valid target."""
        target = TargetCreate(
            name="Test Target",
            domain="example.com",
        )
        assert target.name == "Test Target"
        assert target.domain == "example.com"

    def test_target_with_optional_fields(self):
        """Test target with optional fields."""
        target = TargetCreate(
            name="Test Target",
            domain="example.com",
            description="A test target",
            company="Test Company",
        )
        assert target.description == "A test target"
        assert target.company == "Test Company"

    def test_target_name_required(self):
        """Test target name is required."""
        with pytest.raises(ValidationError):
            TargetCreate(domain="example.com")

    def test_target_domain_required(self):
        """Test target domain is required."""
        with pytest.raises(ValidationError):
            TargetCreate(name="Test Target")


class TestTargetUpdate:
    """Test TargetUpdate schema."""

    def test_partial_update(self):
        """Test partial update works."""
        update = TargetUpdate(name="New Name")
        assert update.name == "New Name"
        assert update.domain is None

    def test_update_with_multiple_fields(self):
        """Test update with multiple fields."""
        update = TargetUpdate(
            name="New Name",
            domain="newexample.com",
        )
        assert update.name == "New Name"
        assert update.domain == "newexample.com"


class TestScanCreate:
    """Test ScanCreate schema."""

    def test_valid_scan_create(self):
        """Test creating valid scan."""
        target_id = uuid.uuid4()
        scan = ScanCreate(
            target_id=target_id,
            scan_type="subdomain",
        )
        assert scan.target_id == target_id
        assert scan.scan_type == "subdomain"

    def test_scan_type_required(self):
        """Test scan type is required."""
        with pytest.raises(ValidationError):
            ScanCreate(target_id=uuid.uuid4())


class TestScanUpdate:
    """Test ScanUpdate schema."""

    def test_scan_status_update(self):
        """Test updating scan status."""
        update = ScanUpdate(status="running")
        assert update.status == "running"

    def test_scan_results_update(self):
        """Test updating scan results."""
        results = '{"vulnerabilities": []}'
        update = ScanUpdate(results=results)
        assert update.results == results

    def test_scan_error_update(self):
        """Test updating scan error message."""
        update = ScanUpdate(error_message="Connection failed")
        assert update.error_message == "Connection failed"


class TestResponseSchemas:
    """Test response schemas."""

    def test_target_response(self):
        """Test target response schema."""
        target_id = uuid.uuid4()
        now = datetime.utcnow()
        
        response = TargetResponse(
            id=target_id,
            name="Test Target",
            domain="example.com",
            created_at=now,
            updated_at=now,
        )
        
        assert response.id == target_id
        assert response.name == "Test Target"

    def test_scan_response(self):
        """Test scan response schema."""
        scan_id = uuid.uuid4()
        target_id = uuid.uuid4()
        now = datetime.utcnow()
        
        response = ScanResponse(
            id=scan_id,
            target_id=target_id,
            scan_type="subdomain",
            status="completed",
            started_at=now,
            completed_at=now,
            results='{"found": 0}',
            created_at=now,
            updated_at=now,
        )
        
        assert response.id == scan_id
        assert response.status == "completed"