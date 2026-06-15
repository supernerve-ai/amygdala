<p align="center">
  <img src="https://img.shields.io/badge/python-3.12+-blue?style=flat-square&logo=python" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/splunk-MCP-orange?style=flat-square&logo=splunk" alt="Splunk MCP">
  <img src="https://img.shields.io/badge/model-Foundation--Sec--8B-purple?style=flat-square" alt="Foundation-Sec">
  <img src="https://img.shields.io/badge/status-alpha-yellow?style=flat-square" alt="Alpha">
</p>

<h1 align="center">🧠 Amygdala</h1>

<p align="center">
  <strong>Autonomous SOC analyst that triages, investigates, and reports security alerts — so your team doesn't have to.</strong>
</p>

<p align="center">
  Built on Splunk MCP &bull; Powered by Foundation-Sec-8B &bull; Zero human-in-the-loop (unless you want one)
</p>

---

## What is Amygdala?

Amygdala is an open-source agentic SOC analyst that connects to Splunk via MCP (Model Context Protocol) using token-based auth, continuously pulls security alerts via SPL queries, and feeds them into [Foundation-Sec-1.1-8B](https://huggingface.co/splunk/foundation-sec-1.1-8b) — Splunk's security-specialized LLM — for threat classification and severity triage.

Based on triage output, Amygdala spawns investigation sub-agents that:
- Correlate related events across your environment
- Trace attacker lateral movement
- Enrich context from surrounding log data
- Score risk based on IOC matches and event correlation

Final output is a **structured incident report** (JSON) plus a **human-readable summary**, pushed to Slack or any webhook in seconds.

**No human needed in the loop unless the escalation threshold is hit.**

## Why Amygdala?

| Problem | Amygdala's Answer |
|---------|-------------------|
| Alert fatigue drowning your SOC team | Autonomous triage cuts noise by 90%+ |
| Analysts spending hours correlating events | Sub-agents correlate in seconds |
| Inconsistent severity classification | Foundation-Sec provides uniform, security-trained evaluation |
| Slow response to critical threats | Real-time pipeline from alert to report |
| Vendor lock-in | Open source, containerized, runs anywhere |

## Architecture

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

## Quick Start

### Prerequisites

- Python 3.12+
- Splunk instance with HEC token
- Splunk MCP server running ([splunk-mcp](https://github.com/splunk/splunk-mcp))
- Foundation-Sec model endpoint (local via Ollama or remote)

### Installation

```bash
# Clone the repo
git clone https://github.com/supernerve-ai/amygdala.git
cd amygdala

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env.local
# Edit .env.local with your credentials
```

### Configuration

1. **Set up your `.env.local`** with Splunk credentials, MCP server URL, and model endpoint
2. **Adjust `config/settings.yaml`** for severity thresholds, polling intervals, and output targets
3. **Customize `prompts/triage_prompt.yaml`** to tune the triage agent's evaluation criteria

### Run

```bash
# Run directly
python -m amygdala.main

# Or via Docker
docker build -t amygdala .
docker run --env-file .env.local amygdala
```

## Project Structure

```
amygdala/
├── amygdala/               # Core application
│   ├── main.py             # Pipeline entrypoint
│   ├── alert_ingestor.py   # Pulls alerts from Splunk via MCP
│   ├── triage_agent.py     # Foundation-Sec severity evaluation
│   ├── investigate_agent.py # Correlation sub-agents
│   ├── mcp_client.py       # Splunk MCP connection client
│   ├── report_builder.py   # Structured report generation
│   └── output_handler.py   # Slack/webhook delivery
├── config/                 # Runtime configuration
│   └── settings.yaml       # Main config file
├── prompts/                # Agent prompt templates
│   └── triage_prompt.yaml  # Triage evaluation prompt
├── tests/                  # Test suite
├── examples/               # Sample alerts and configs
├── Dockerfile              # Container build
├── requirements.txt        # Python dependencies
└── .env.example            # Environment template
```

## Configuration Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `SPLUNK_HOST` | Splunk instance URL | — |
| `SPLUNK_TOKEN` | HEC authentication token | — |
| `SPLUNK_INDEX` | Index to query | `main` |
| `MCP_SERVER_URL` | MCP server endpoint | `http://localhost:8080` |
| `MODEL_ENDPOINT` | Foundation-Sec API endpoint | `http://localhost:11434` |
| `MODEL_NAME` | Model identifier | `foundation-sec` |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook | — |
| `SLACK_CHANNEL` | Target Slack channel | `#security-alerts` |
| `LOG_LEVEL` | Logging verbosity | `INFO` |

## Community

- 💬 [Discussions](https://github.com/supernerve-ai/amygdala/discussions) — Ask questions, share ideas
- 🐛 [Issues](https://github.com/supernerve-ai/amygdala/issues) — Report bugs, request features
- 📖 [Contributing](CONTRIBUTING.md) — How to get involved
- 🗺️ [Roadmap](ROADMAP.md) — Where we're headed

## License

MIT — see [LICENSE](LICENSE) for details.

## Security

Found a vulnerability? Please report it responsibly. See [SECURITY.md](SECURITY.md) for our disclosure policy.

---

<p align="center">
  <em>Named after the brain's threat detection center — because your SOC deserves one that never sleeps.</em>
</p>
