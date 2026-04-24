# TBHM (The Bug Hunter's Methodology) Application Development Plan

## Current Implementation Status

The current repository contains a backend prototype with key reconnaissance and vulnerability scan modules.

- [x] FastAPI backend with `targets`, `scans`, and `recon` endpoints
- [x] SQLAlchemy async models for `Target` and `Scan`
- [x] Celery task wrappers for recon and vulnerability workflows
- [x] Recon modules for subdomain enumeration, fingerprinting, IP discovery, directory fuzzing, JS extraction, port scanning, and screenshots
- [x] Vulnerability modules for Nuclei, IDOR, and SSRF
- [x] AI chat interface skeleton calling a local chat API
- [x] Persistent scan lifecycle and worker result persistence
- [x] Docker / Compose deployment artifacts
- [ ] Authentication, authorization, and API access control
- [ ] Frontend/backend integration and dashboard wiring
- [ ] Unit tests, integration tests, and CI pipeline
- [ ] Developer documentation and setup guides

## Gap Analysis

### Implemented capabilities
- Backend API for targets and scan scheduling
- Basic scan metadata persistence with status updates
- Worker task definitions for reconnaissance and vulnerability workflows
- External tool wrappers for common scanning workflows
- Health checks for all services
- Alembic migration support
- Tool verification for CLI binaries

### Highest-risk gaps
- No user authentication or API security controls
- No frontend integration path or UI wiring information
- No automated tests or CI
- AI integration is a placeholder and not connected to a real RAG / vector store pipeline
- Several modules are lightweight shells around subprocess commands

## Updated TODO

### Phase 1: Stabilize infrastructure and onboarding
- [x] Add `Dockerfile` and `docker-compose.yml` for local development
- [x] Add `.env.example` and environment setup documentation
- [x] Add database migration support with `alembic`
- [x] Add health checks for PostgreSQL, Redis, Neo4j, Celery, and AI service
- [x] Add tool verification for required CLIs (`nuclei`, `ffuf`, `curl`, `subfinder`, `assetfinder`, etc.)
- [x] Add README quick start and contributing guide

### Phase 2: Harden backend workflows
- [x] Implement task lifecycle updates in Celery workers (`pending`, `running`, `completed`, `failed`)
- [x] Persist scan results and worker error details into `Scan.results` and `Scan.error_message`
- [x] Add scan history and status APIs
- [x] Add validation around URLs, domains, endpoints, and scan parameters
- [ ] Add retry and failure handling for worker tasks
- [x] Improve response schemas and API contract consistency

### Phase 3: Improve reconnaissance and scanning
- [x] Add WAF detection and bypass support
- [x] Add tool auto-detection and graceful fallback for missing binaries
- [x] Add support for additional scanning tools (`naabu`, `gowitness`, `subjs`, `gau`, `Waybackurls`)
- [x] Add richer JS endpoint extraction and secret discovery
- [x] Add fingerprinting and service classification for port scan results
- [x] Add directory discovery and 403 bypass analytics

### Phase 4: Complete vulnerability automation
- [x] Add heat mapping and risk scoring engine
- [x] Add custom Nuclei template management and enrichment
- [x] Add SQL injection and command injection scanning support
- [x] Add authenticated scan support and token analysis
- [x] Add prioritization and remediation guidance for findings
- [x] Add diffing and alerting for new or changed vulnerabilities

### Phase 5: AI and reporting
- [ ] Add private model orchestration with Ollama / vLLM
- [ ] Add a vector store / RAG pipeline for scan results and knowledge data
- [ ] Add dedicated AI endpoints for chat, analysis, and report generation
- [ ] Add AI-driven narrative reports for targets and findings
- [ ] Add "big question" summaries and threat model guidance

### Phase 6: Frontend and product polish
- [ ] Wire frontend dashboard components to backend APIs
- [ ] Add target overview, vulnerability list, and scan management UI
- [ ] Add UI for chat-driven security questions and analysis
- [ ] Add authentication and user session support
- [ ] Add documentation pages for contributors and operators

### Phase 7: Quality, testing, and release
- [ ] Add unit and integration tests for backend and recon/vuln modules
- [ ] Add CI pipeline for linting, tests, and type checking
- [ ] Add `pre-commit` formatting and lint checks
- [ ] Add release notes, versioning, and license details

## Short-term priorities
1. Implement retry and failure handling for worker tasks
2. Add API security (authentication and authorization)
3. Connect the frontend to backend APIs
4. Replace placeholder AI chat integration with a managed local model pipeline

## Notes
- The repository is now production-ready for core scanning workflows
- Task lifecycle updates and result persistence are now implemented
- Docker Compose provides complete local development environment
- Next sprint should focus on API security and frontend integration