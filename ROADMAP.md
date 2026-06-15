# Roadmap

## Amygdala Development Roadmap

### v0.1 — Foundation (Current)
- [x] Core pipeline: ingest → triage → investigate → report → notify
- [x] Splunk MCP client with token-based auth
- [x] Foundation-Sec-1.1-8B triage integration
- [x] Basic event correlation in investigation sub-agents
- [x] Slack webhook output
- [x] Docker containerization
- [x] Configuration via YAML + env vars

### v0.2 — Enrichment & Accuracy
- [ ] IOC feed integration (VirusTotal, AbuseIPDB, OTX)
- [ ] MITRE ATT&CK technique mapping in triage output
- [ ] Confidence scoring with explainability
- [ ] Alert deduplication and grouping
- [ ] Improved SPL query templates for common alert types
- [ ] Structured output parsing from Foundation-Sec responses

### v0.3 — Observability & Reliability
- [ ] Prometheus metrics endpoint
- [ ] Health check API
- [ ] Retry logic with exponential backoff for MCP/model calls
- [ ] Dead letter queue for failed alerts
- [ ] Pipeline run history and audit trail
- [ ] Configurable rate limiting

### v0.4 — Multi-Source & Integrations
- [ ] Support additional SIEM sources (Elastic, Sentinel)
- [ ] PagerDuty / Opsgenie escalation
- [ ] Jira / ServiceNow ticket creation
- [ ] Email notification channel
- [ ] Custom webhook payload templates

### v0.5 — Learning & Feedback
- [ ] Analyst feedback loop (confirm/reject triage decisions)
- [ ] Tunable severity thresholds per alert category
- [ ] Historical pattern detection
- [ ] Auto-suppression of known false positives
- [ ] Dashboard UI for triage review

### Future
- [ ] Multi-tenant support
- [ ] Plugin architecture for custom investigation steps
- [ ] Fine-tuning pipeline for org-specific alert patterns
- [ ] Real-time streaming mode (beyond polling)
- [ ] Role-based access control for reports

---

*This roadmap is subject to change based on community feedback and priorities. [Open an issue](https://github.com/supernerve-ai/amygdala/issues) to suggest features or vote on existing proposals.*
