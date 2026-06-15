# Architecture Diagram

## Amygdala — Autonomous SOC Analyst Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          AMYGDALA PIPELINE                                  │
└─────────────────────────────────────────────────────────────────────────────┘

 ┌──────────────┐         ┌──────────────┐         ┌───────────────────┐
 │              │  Token   │              │  HTTP    │                   │
 │  Splunk HEC  │─────────▶│  MCP Server  │─────────▶│  Alert Ingestor   │
 │              │  Auth    │              │  /tools  │                   │
 └──────────────┘         └──────────────┘         └─────────┬─────────┘
                                                             │
                                                    SPL Query Results
                                                             │
                                                             ▼
                                                   ┌───────────────────┐
                                                   │                   │
                                                   │   Triage Agent    │
                                                   │                   │
                                                   │ ┌───────────────┐ │
                                                   │ │Foundation-Sec │ │
                                                   │ │  1.1-8B LLM   │ │
                                                   │ └───────────────┘ │
                                                   │                   │
                                                   │  Severity: 1-10   │
                                                   │  Category         │
                                                   │  Summary          │
                                                   │  Action           │
                                                   └─────────┬─────────┘
                                                             │
                                              ┌──────────────┼──────────────┐
                                              │     severity >= threshold?   │
                                              └──────┬───────────────┬──────┘
                                                     │ YES           │ NO
                                                     ▼               ▼
                                              ┌─────────────┐   [Log & Skip]
                                              │ Investigate │
                                              │   Agent     │
                                              └──────┬──────┘
                                                     │
                                    ┌────────────────┼────────────────┐
                                    │                │                │
                                    ▼                ▼                ▼
                          ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
                          │  Correlate   │  │  IOC Check   │  │  Timeline    │
                          │  Sub-Agent   │  │  Sub-Agent   │  │  Sub-Agent   │
                          │              │  │              │  │              │
                          │ Search by IP │  │ VirusTotal   │  │ Sort events  │
                          │ Find related │  │ AbuseIPDB    │  │ by timestamp │
                          │ events       │  │ OTX          │  │              │
                          └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
                                 │                 │                 │
                                 └─────────────────┼─────────────────┘
                                                   │
                                                   ▼
                                         ┌───────────────────┐
                                         │   Risk Scoring    │
                                         │                   │
                                         │ risk = severity/10│
                                         │   + correlation   │
                                         │   + IOC bonus     │
                                         │   (max 1.0)       │
                                         └─────────┬─────────┘
                                                   │
                                                   ▼
                                         ┌───────────────────┐
                                         │  Report Builder   │
                                         │                   │
                                         │ • JSON (machine)  │
                                         │ • Summary (human) │
                                         │ • Slack blocks    │
                                         └─────────┬─────────┘
                                                   │
                                                   ▼
                                         ┌───────────────────┐
                                         │  Output Handler   │
                                         │                   │
                                         │ • Slack webhook   │
                                         │ • Custom webhook  │
                                         │ • Stdout (debug)  │
                                         └───────────────────┘
                                                   │
                                    ┌──────────────┼──────────────┐
                                    │              │              │
                                    ▼              ▼              ▼
                             ┌───────────┐  ┌───────────┐  ┌───────────┐
                             │   Slack   │  │  Webhook  │  │  stdout   │
                             │  #alerts  │  │  (JSON)   │  │  (debug)  │
                             └───────────┘  └───────────┘  └───────────┘
```

## Data Flow Summary

| Stage | Input | Output | Component |
|-------|-------|--------|-----------|
| 1. Ingest | SPL query | Alert list | `alert_ingestor.py` |
| 2. Triage | Raw alert | Severity + category | `triage_agent.py` + Foundation-Sec |
| 3. Gate | Triage result | Pass/skip decision | Threshold comparison |
| 4. Investigate | Alert + triage | Correlations + IOCs + timeline | `investigate_agent.py` |
| 5. Score | Investigation data | Risk score (0.0–1.0) | Risk formula |
| 6. Report | All results | JSON + human summary | `report_builder.py` |
| 7. Deliver | Report | Slack message / webhook | `output_handler.py` |

## Technology Stack

```
┌─────────────────────────────────────────────┐
│              Application Layer               │
│  Python 3.12+ · asyncio · httpx · pydantic  │
├─────────────────────────────────────────────┤
│              AI / ML Layer                    │
│  Foundation-Sec-1.1-8B (Splunk LLM)         │
│  Ollama / OpenAI-compatible endpoint         │
├─────────────────────────────────────────────┤
│              Transport Layer                  │
│  MCP (Model Context Protocol)                │
│  Token-based auth · TLS in production        │
├─────────────────────────────────────────────┤
│              Data Layer                       │
│  Splunk Enterprise / Splunk Cloud            │
│  SPL queries · HEC indices                   │
├─────────────────────────────────────────────┤
│              Delivery Layer                   │
│  Slack SDK · HTTP webhooks · stdout          │
├─────────────────────────────────────────────┤
│              Infrastructure                   │
│  Docker · GitHub Actions CI/CD               │
└─────────────────────────────────────────────┘
```
