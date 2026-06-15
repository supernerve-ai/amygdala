# Changelog

All notable changes to Amygdala will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffolding
- Alert ingestion pipeline via Splunk MCP server
- Foundation-Sec-1.1-8B triage agent for threat classification
- Investigation sub-agents with event correlation
- Structured JSON + human-readable incident reports
- Slack webhook output handler
- Docker containerization
- Configuration via YAML + environment variables
- Sample alert data for local testing

### Security
- Token-based auth for Splunk MCP connection
- Environment variable isolation for all secrets
- TLS enforcement for production Splunk endpoints

## [0.1.0] - 2026-06-15

### Added
- First public release
- Core pipeline: ingest -> triage -> investigate -> report -> notify
- MCP client for Splunk connectivity
- Foundation-Sec model integration
- Configurable severity thresholds
- Slack notification support
