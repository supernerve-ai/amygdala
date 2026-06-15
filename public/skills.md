# Amygdala — Skills & Capabilities

## What Amygdala Can Do

Amygdala is an autonomous SOC (Security Operations Center) analyst agent. It is designed to handle security alert triage and investigation without human intervention.

### Core Skills

1. **Alert Ingestion** — Continuously pulls security alerts from Splunk via MCP (Model Context Protocol) using SPL queries.

2. **Threat Classification** — Feeds alerts into Foundation-Sec-1.1-8B, a security-specialized large language model, for accurate threat categorization.

3. **Severity Triage** — Assigns severity scores (1–10) to alerts based on threat type, attack vector, and environmental context.

4. **Event Correlation** — Spawns investigation sub-agents that search for related events by source IP, user, hostname, and timeframe.

5. **Lateral Movement Tracing** — Traces attacker movement across systems by correlating authentication events, process creation, and network connections.

6. **IOC Enrichment** — Cross-references indicators of compromise (IPs, domains, hashes) against threat intelligence feeds.

7. **Timeline Reconstruction** — Builds chronological event timelines to visualize attack progression.

8. **Risk Scoring** — Calculates composite risk scores combining severity, correlation density, and IOC matches.

9. **Incident Reporting** — Generates structured JSON reports for automation and human-readable summaries for analysts.

10. **Escalation & Notification** — Pushes reports to Slack or custom webhooks. Escalates to human analysts only when thresholds are exceeded.

### Technical Capabilities

- Async pipeline architecture for high-throughput alert processing
- Token-based authentication for secure Splunk connectivity
- Configurable severity thresholds per alert category
- Containerized deployment (Docker) for any environment
- Environment-variable-driven configuration (no hardcoded secrets)
- Graceful degradation on individual alert failures

### Supported Integrations

| Integration | Status |
|-------------|--------|
| Splunk (via MCP) | ✅ Supported |
| Foundation-Sec-1.1-8B | ✅ Supported |
| Slack Webhooks | ✅ Supported |
| Custom Webhooks | ✅ Supported |
| VirusTotal | 🔜 Planned |
| AbuseIPDB | 🔜 Planned |
| MITRE ATT&CK | 🔜 Planned |
| PagerDuty | 🔜 Planned |
| Jira/ServiceNow | 🔜 Planned |

---

*For more details, see the [README](https://github.com/supernerve-ai/amygdala) or [Roadmap](https://github.com/supernerve-ai/amygdala/blob/main/ROADMAP.md).*
