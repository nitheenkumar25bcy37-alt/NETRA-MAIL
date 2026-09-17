> Historical audit. For current authentication, detector behavior and measured limits, see [upgrade validation](docs/UPGRADE_VALIDATION.md); earlier missing-auth observations must not be presented as the current implementation.

# Phase 7 Audit

## Current architecture

- FastAPI backend: `backend/main.py`
- SQLite persistence: `backend/database.py`
- Streamlit dashboard: `dashboard/app.py`
- Gmail Manifest V3 extension: `extension/`
- Optional IP provider: `backend/intelligence/ip_provider.py`
- Bounded DNS provider: `backend/intelligence/domain_provider.py`
- Evidence storage: configured by `NETRA_EVIDENCE_STORAGE_DIR`
- Reports: JSON, escaped HTML, optional ReportLab PDF

## Routes and mutation classes

- Read-only: health, readiness, summaries, email/campaign/case/evidence/report retrieval.
- Analysis-producing: v1 text/email/EML and v2 text/upload analysis.
- Evidence-mutating: evidence registration, versions, case evidence links, verification events.
- Case-mutating: case/campaign updates, notes, tags, links.
- Report-generating: case report creation.

No application authentication or authorization is currently implemented. Deployment must place the API behind an authenticated gateway or add an authentication layer before exposing mutation endpoints publicly.

## Data and provider review

- Raw bytes are parsed in memory and preserved in the evidence storage service for v2 ingestion; v2 analysis payloads retain SHA-256 and metadata rather than raw bytes.
- SQLite stores analyses, campaigns, cases, evidence metadata, custody events, and report metadata. Raw files are stored once under the configured evidence directory.
- IP enrichment is optional and returns unavailable results without fake values.
- DNS enrichment is bounded and best effort.
- URL expansion is disabled by default; attachments are never executed.
- CORS is configured by `NETRA_ALLOWED_ORIGINS`.

## Known hardening gaps before Phase 7 changes

- Text, MIME-part, URL, header, and archive-member limits were not centralized.
- Analysis/report/intelligence routes had no lightweight request rate guard.
- No readiness endpoint existed.
- Legacy test modules referenced renamed classes and old result keys.
- No deterministic evaluation dataset or measured evaluation runner existed.
- Deployment documentation and environment template were incomplete.

## Phase 7 goals

1. Add bounded input/resource handling and a deployment-ready rate-limit abstraction.
2. Add safe readiness and sanitized operational logging.
3. Add deterministic synthetic evaluation data and measured JSON/Markdown output.
4. Restore non-destructive compatibility aliases and clean test discovery.
5. Add deployment/environment/demo documentation without claiming production authentication.

## Security boundary

Authentication, HTTPS, durable production database operations, secret management, and external provider governance remain deployment responsibilities. The local application does not claim to identify a human attacker.
