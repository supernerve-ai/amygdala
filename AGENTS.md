# AGENTS.md

Guidelines for AI agents working on the Amygdala codebase.

---

## Project Overview

Amygdala is an open-source agentic SOC analyst built on Splunk's AI capabilities. It connects to Splunk via MCP server using token-based auth, pulls security alerts via SPL queries, and feeds them into Foundation-Sec-1.1-8B for threat classification and severity triage. Investigation sub-agents correlate events, trace attacker movement, and enrich context. Output is structured JSON incident reports plus human-readable summaries pushed to Slack or webhooks.

### Architecture

```
alerts (Splunk SPL) → AlertIngestor → TriageAgent (Foundation-Sec LLM)
    → InvestigateAgent (correlation sub-agents) → ReportBuilder → OutputHandler (Slack/webhook)
```

### Key Modules

| Module | Purpose |
|--------|---------|
| `amygdala/main.py` | Pipeline entrypoint — orchestrates ingest → triage → investigate → report → notify |
| `amygdala/alert_ingestor.py` | Fetches alerts from Splunk via MCP |
| `amygdala/triage_agent.py` | Evaluates alert severity using Foundation-Sec model |
| `amygdala/investigate_agent.py` | Spawns sub-agents to correlate events and trace attacker movement |
| `amygdala/mcp_client.py` | MCP server connection client (Splunk transport layer) |
| `amygdala/report_builder.py` | Builds structured JSON + human-readable incident reports |
| `amygdala/output_handler.py` | Pushes reports to Slack webhooks or other destinations |
| `config/settings.yaml` | Runtime configuration (env-var interpolated) |
| `prompts/triage_prompt.yaml` | System prompt template for the triage LLM |

---

## Dev Environment Setup

1. **Python version**: 3.12+ required (matches Dockerfile base image).
2. **Clone and configure**:
   ```bash
   cp .env.example .env
   # Fill in SPLUNK_HOST, SPLUNK_TOKEN, MCP_SERVER_URL, MODEL_ENDPOINT, SLACK_WEBHOOK_URL
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Run locally**:
   ```bash
   python -m amygdala.main
   ```
5. **Run via Docker**:
   ```bash
   docker build -t amygdala .
   docker run --env-file .env amygdala
   ```

### Dev Environment Tips

- Configuration lives in `config/settings.yaml` — it interpolates env vars at runtime via `${VAR_NAME}` syntax.
- Prompt templates are in `prompts/` as YAML files. Edit these to tune triage behavior without touching code.
- The MCP client (`amygdala/mcp_client.py`) is a thin HTTP wrapper — if the MCP server spec changes, this is the only file to update.
- Use `LOG_LEVEL=DEBUG` in your `.env` to get verbose pipeline output during development.
- The `examples/sample_alert.json` file contains a representative alert payload for local testing without a live Splunk connection.

---

## Testing Instructions

- Tests live in the `tests/` directory.
- Run the full test suite:
  ```bash
  pytest tests/ -v
  ```
- Run a specific test file:
  ```bash
  pytest tests/test_triage.py -v
  ```
- Run a specific test by name pattern:
  ```bash
  pytest tests/ -k "test_name_pattern" -v
  ```
- **Before committing**: all tests must pass. Run `pytest` and fix any failures.
- **After moving files or changing imports**: verify nothing broke by running the full suite.
- **Add or update tests** for any code you change, even if nobody asked. Coverage of the triage and investigation logic is critical since these drive automated decisions.
- Type checking (if mypy is configured):
  ```bash
  mypy amygdala/
  ```

---

## Code Style & Conventions

- **Async-first**: The pipeline is fully async. Use `async/await` for any I/O-bound work. Don't introduce synchronous blocking calls.
- **Dataclasses for results**: Structured outputs use `@dataclass` (see `TriageResult`, `InvestigationResult`). Keep this pattern for new result types.
- **Logging**: Use `logging.getLogger(__name__)` in every module. Log at appropriate levels — `INFO` for pipeline milestones, `DEBUG` for internal details, `WARNING`/`ERROR` for failures.
- **Environment variables**: All secrets and connection strings come from env vars loaded via `python-dotenv`. Never hardcode credentials.
- **Configuration**: Runtime tuning goes in `config/settings.yaml`. Code shouldn't contain magic numbers — pull from config.
- **Error handling**: Wrap external calls (MCP, model endpoint, Slack) in try/except with meaningful error messages. The pipeline should degrade gracefully, not crash on a single alert failure.
- **Imports**: Use relative imports within the `amygdala` package (e.g., `from .mcp_client import MCPClient`).

---

## PR Instructions

- **Title format**: `[amygdala] <Short descriptive title>`
- **Before committing**:
  1. Run `pytest tests/ -v` — all green.
  2. Verify no hardcoded secrets or credentials in the diff.
  3. If you changed dependencies, update `requirements.txt`.
  4. If you added new env vars, update both `.env.example` and `.env.local`.
- **PR description** should include:
  - What changed and why.
  - How it was tested (which tests added/modified, or manual verification steps).
  - Any config or env changes required to deploy.
- **Security-sensitive changes** (auth logic, MCP token handling, webhook endpoints) must be called out explicitly in the PR description.

---

## Security Considerations

- **Never commit** `.env`, `.env.local`, or any file containing real tokens/secrets.
- The Splunk token grants read access to security indices — treat it as highly sensitive.
- MCP server communication uses token-based auth. Verify TLS in production (`SPLUNK_HOST` should always be `https://`).
- Webhook URLs (Slack, etc.) are secrets — don't log them or include them in error messages.
- The Foundation-Sec model endpoint may be local (Ollama) or remote — either way, don't expose it publicly.

---

## Useful Context

- **Splunk SPL queries** power the alert ingestion. If you're unfamiliar with SPL, check Splunk's [Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference).
- **Foundation-Sec-1.1-8B** is Splunk's security-specialized LLM. It expects security-domain prompts — generic prompts will produce worse results.
- **MCP (Model Context Protocol)** is the transport layer between Amygdala and Splunk. The client calls tools exposed by the MCP server (`splunk_search`, etc.).
- **Escalation threshold** is configured in `config/settings.yaml` under `triage.severity_threshold`. Alerts below this are logged but not reported.
- **Output is dual-format**: structured JSON (for downstream automation) and human-readable summary (for Slack/humans).
