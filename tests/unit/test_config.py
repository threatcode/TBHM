"""Unit tests for core configuration."""

import pytest
from pydantic import ValidationError

from tbhm.core.config import Settings


class TestSettings:
    """Test settings configuration."""

    def test_default_settings(self):
        """Test default settings are loaded."""
        settings = Settings()
        assert settings.PROJECT_NAME == "TBHM"
        assert settings.SERVER_PORT == 8000

    def test_database_uri_constructed(self):
        """Test database URI is constructed from components."""
        settings = Settings(
            POSTGRES_USER="testuser",
            POSTGRES_PASSWORD="testpass",
            POSTGRES_SERVER="localhost",
            POSTGRES_DB="testdb",
            POSTGRES_PORT=5432,
        )
        assert "testuser" in settings.DATABASE_URI
        assert "testpass" in settings.DATABASE_URI

    def test_celery_broker_url_constructed(self):
        """Test Celery broker URL is constructed."""
        settings = Settings(REDIS_HOST="redis.local")
        assert settings.CELERY_BROKER_URL is not None
        assert "redis.local" in settings.CELERY_BROKER_URL

    def test_custom_settings(self):
        """Test custom settings override."""
        settings = Settings(
            PROJECT_NAME="CustomProject",
            SERVER_PORT=9000,
        )
        assert settings.PROJECT_NAME == "CustomProject"
        assert settings.SERVER_PORT == 9000

    def test_cors_origins_validator(self):
        """Test CORS origins are properly parsed."""
        settings = Settings(
            BACKEND_CORS_ORIGINS="http://localhost:3000,http://localhost:8080"
        )
        assert len(settings.BACKEND_CORS_ORIGINS) == 2
        assert "http://localhost:3000" in settings.BACKEND_CORS_ORIGINS