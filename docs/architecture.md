# Architecture

## High-Level Overview

Amygdala is a pipeline-based autonomous SOC analyst. Alerts flow through a series of stages, each handled by a dedicated component. The system is fully async, containerized, and designed to process hundreds of alerts without human intervention.

```
┌──────────────┐     ┌──────────────┐     ┌───────────────────┐
│  Splunk HEC  │────▶│  MCP Server  │────▶│  Alert Ingestor   │
└──────────────┘     └──────────────┘     └─────────┬─────────┘
                                                    │
                                                    ▼
                                          ┌───────────────────┐
                                          │   Triage Agent    │
                                          │ (Foundation-Sec)  │
                                          └─────────┬─────────┘
                                                    │
                                    ┌───────────────┼───────────────┐
                                    ▼               ▼               ▼
                            ┌──────────────┐ ┌──────────┐ ┌──────────────┐
                            │  Correlate   │ │ IOC Check│ │   Timeline   │
                            │  Sub-Agent   │ │ Sub-Agent│ │  Sub-Agent   │
                            └──────┬───────┘ └────┬─────┘ └──────┬───────┘
                                   └──────────────┼──────────────┘
                                                  ▼
                                        ┌───────────────────┐
                                        │  Report Builder   │
                                        └─────────┬─────────┘
                                                  ▼
                                        ┌───────────────────┐
                                        │  Output Handler   │
                                        │ (Slack/Webhooks)  │
                                        └───────────────────┘
```

---

## Pipeline Stages

### 1. Alert Ingestion

**Component:** `amygdala/alert_ingestor.py`

- Connects to Splunk via MCP (Model Context Protocol) server
- Executes SPL queries against configured indices
- Pulls alerts within the configured time window (default: last 15 minutes)
- Returns raw alert dictionaries for downstream processing

**Data Flow:** Splunk → MCP Server → AlertIngestor → list of alert dicts

---

### 2. Triage

**Component:** `amygdala/triage_agent.py`

- Receives raw alert data from the ingestor
- Constructs a prompt using the template in `prompts/triage_prompt.yaml`
- Sends the prompt to Foundation-Sec-1.1-8B via HTTP API
- Parses the model response into a structured `TriageResult`:
  - `severity` (1–10 scale)
  - `category` (threat type classification)
  - `summary` (brief description)
  - `recommended_action` (next step)

**Decision Gate:** If `severity >= threshold` (configured in `settings.yaml`), the alert proceeds to investigation. Otherwise it's logged and skipped.

---

### 3. Investigation

**Component:** `amygdala/investigate_agent.py`

Spawns multiple sub-agents to build a complete picture of the alert:

#### Correlation Sub-Agent
- Searches for events matching the alert's source IP within the last hour
- Uses SPL queries via MCP to find related activity
- Returns correlated event list

#### IOC Check Sub-Agent
- Extracts indicators (IPs, domains, hashes) from the alert
- Cross-references against threat intelligence feeds
- Returns matched IOCs

#### Timeline Sub-Agent
- Combines the original alert with all correlated events
- Sorts by timestamp to reconstruct chronological order
- Returns an ordered event timeline

**Output:** `InvestigationResult` containing:
- `correlated_events` — related events found
- `ioc_matches` — confirmed indicators of compromise
- `timeline` — chronological event sequence
- `risk_score` — composite score (0.0–1.0)
- `recommendation` — ESCALATE or MONITOR

---

### 4. Report Generation

**Component:** `amygdala/report_builder.py`

- Receives alert, triage result, and investigation result
- Generates two output formats:
  - **Structured JSON** — for downstream automation and SIEM ingestion
  - **Human-readable summary** — for Slack messages and analyst review
- Includes all relevant metadata: timestamps, severity, risk score, IOCs, timeline, recommendation

---

### 5. Output & Notification

**Component:** `amygdala/output_handler.py`

- Delivers the report to configured destinations:
  - **Slack** — via incoming webhook to a specified channel
  - **Custom webhooks** — HTTP POST with JSON payload
- Handles delivery failures gracefully (logs errors, does not crash pipeline)
- Supports escalation routing based on severity/risk thresholds

---

## Supporting Components

### MCP Client

**Component:** `amygdala/mcp_client.py`

- Thin HTTP client wrapping MCP tool calls
- Sends tool invocations to the MCP server (e.g., `splunk_search`)
- Handles timeouts and connection management
- Single point of change if MCP protocol evolves

### Configuration

**File:** `config/settings.yaml`

- All runtime parameters in one place
- Supports environment variable interpolation via `${VAR_NAME}` syntax
- Controls: time windows, severity thresholds, output targets, logging

### Prompt Templates

**File:** `prompts/triage_prompt.yaml`

- System prompt and evaluation criteria for the triage LLM
- Editable without code changes
- Defines how Foundation-Sec should classify and score threats

---

## Data Models

### TriageResult

```python
@dataclass
class TriageResult:
    severity: int          # 1–10 scale
    threshold: int         # configured severity threshold
    category: str          # threat classification
    summary: str           # brief description
    recommended_action: str  # next step
```

### InvestigationResult

```python
@dataclass
class InvestigationResult:
    correlated_events: list[dict]  # related events
    ioc_matches: list[str]         # confirmed IOCs
    timeline: list[dict]           # chronological events
    risk_score: float              # 0.0–1.0 composite
    recommendation: str            # ESCALATE or MONITOR
```

---

## Deployment

### Local

```bash
python -m amygdala.main
```

### Docker

```bash
docker build -t amygdala .
docker run --env-file .env.local amygdala
```

### Environment Requirements

- Python 3.12+
- Network access to Splunk MCP server
- Network access to Foundation-Sec model endpoint
- (Optional) Network access to Slack webhook URL

---

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Splunk access | Token-based auth via HEC |
| MCP transport | HTTP with token in request |
| Secrets management | Environment variables (never in code) |
| Production transport | TLS enforced (HTTPS) |
| Container isolation | Non-root Docker user recommended |
| Output delivery | Webhook URLs treated as secrets |

---

## Scaling Considerations

- **Horizontal:** Run multiple container instances with partitioned alert queries
- **Vertical:** Async pipeline handles concurrent alerts within a single instance
- **Rate limiting:** Configurable polling interval and MCP timeout prevent overloading Splunk
- **Failure isolation:** Individual alert failures don't crash the pipeline — logged and skipped

---

*For the roadmap of planned enhancements, see [ROADMAP.md](../ROADMAP.md).*
