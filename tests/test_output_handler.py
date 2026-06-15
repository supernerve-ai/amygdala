"""Tests for the output handler."""

import pytest

from amygdala.output_handler import OutputHandler


class TestOutputHandler:
    """Tests for OutputHandler initialization and message formatting."""

    def test_default_initialization(self):
        handler = OutputHandler()
        assert handler.slack_channel == "#security-alerts"

    def test_no_webhook_by_default(self):
        handler = OutputHandler()
        assert handler.slack_webhook is None

    def test_custom_channel(self, monkeypatch):
        monkeypatch.setenv("SLACK_CHANNEL", "#soc-critical")
        handler = OutputHandler()
        assert handler.slack_channel == "#soc-critical"

    def test_slack_message_formatting(self):
        handler = OutputHandler()
        report = {
            "report_id": "INC-20260615120000",
            "triage": {
                "severity": 8,
                "category": "malware",
                "summary": "Malicious download detected",
                "recommended_action": "Isolate host",
            },
            "investigation": {
                "risk_score": 0.92,
                "ioc_matches": ["bad-ip", "bad-domain"],
                "recommendation": "ESCALATE",
                "correlated_events_count": 5,
                "timeline_events": 8,
            },
        }
        message = handler._format_slack_message(report)

        assert message["channel"] == "#security-alerts"
        assert len(message["blocks"]) == 4
        assert message["blocks"][0]["type"] == "header"
        assert "INC-20260615120000" in message["blocks"][0]["text"]["text"]

    def test_slack_message_severity_field(self):
        handler = OutputHandler()
        report = {
            "report_id": "INC-TEST",
            "triage": {
                "severity": 10,
                "category": "privilege_escalation",
                "summary": "Root compromise",
                "recommended_action": "Isolate",
            },
            "investigation": {
                "risk_score": 1.0,
                "ioc_matches": [],
                "recommendation": "ESCALATE",
                "correlated_events_count": 4,
                "timeline_events": 5,
            },
        }
        message = handler._format_slack_message(report)
        fields = message["blocks"][1]["fields"]
        severity_field = fields[0]["text"]
        assert "10/10" in severity_field
