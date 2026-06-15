"""Tests for the triage agent."""

import pytest

from amygdala.triage_agent import TriageAgent, TriageResult


class TestTriageResult:
    """Tests for TriageResult dataclass."""

    def test_triage_result_creation(self):
        result = TriageResult(
            severity=7,
            threshold=5,
            category="malware",
            summary="Detected malicious payload",
            recommended_action="isolate host",
        )
        assert result.severity == 7
        assert result.threshold == 5
        assert result.category == "malware"

    def test_severity_above_threshold(self):
        result = TriageResult(
            severity=8,
            threshold=5,
            category="brute_force",
            summary="Multiple failed logins",
            recommended_action="block IP",
        )
        assert result.severity >= result.threshold

    def test_severity_below_threshold(self):
        result = TriageResult(
            severity=3,
            threshold=5,
            category="other",
            summary="Low priority event",
            recommended_action="monitor",
        )
        assert result.severity < result.threshold


class TestTriageAgent:
    """Tests for TriageAgent."""

    def test_agent_initialization(self):
        agent = TriageAgent()
        assert agent.model_name is not None
        assert agent.threshold == 5

    def test_build_prompt(self):
        agent = TriageAgent()
        alert = {"id": "test-001", "src_ip": "10.0.0.1"}
        prompt = agent._build_prompt(alert)
        assert "10.0.0.1" in prompt
