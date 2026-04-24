# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-04-24

### Added
- FastAPI backend with targets, scans, and recon endpoints
- SQLAlchemy async models for Target and Scan
- Celery task wrappers for recon and vulnerability workflows
- Recon modules for subdomain enumeration, fingerprinting, IP discovery, directory fuzzing, JS extraction, port scanning, and screenshots
- Vulnerability modules for Nuclei, IDOR, SSRF, SQL injection, and command injection
- WAF detection and bypass support
- Tool auto-detection and graceful fallback for missing binaries
- Health checks for PostgreSQL, Redis, Neo4j, Celery, and AI service
- Dockerfile and docker-compose.yml for local development
- Alembic database migration support
- Task lifecycle updates in Celery workers (pending, running, completed, failed)
- Persist scan results and worker error details
- Pre-commit hooks for code formatting and linting
- Unit tests for core modules
- GitHub Actions CI pipeline

### Changed
- Updated pyproject.toml with expanded dev dependencies
- Improved tool verification CLI

### Fixed
- Scan status not updating after worker completion
- Results not being persisted to database

## [0.0.1] - 2024-01-01

### Added
- Initial prototype release