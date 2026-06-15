"""Tests for the investigation agent."""

import pytest

from amygdala.investigate_agent import InvestigateAgent, InvestigationResult
from amygdala.triage_agent import TriageResult


class TestInvestigationResult:
    """Tests for InvestigationResult dataclass."""

    def test_default_creation(self):
        result = InvestigationResult()
        assert result.correlated_events == []
        assert result.ioc_matches == []
        assert result.timeline == []
        assert result.risk_score == 0.0
        assert result.recommendation == ""

    def test_creation_with_data(self):
        result = InvestigationResult(
            correlated_events=[{"id": "1"}, {"id": "2"}],
            ioc_matches=["1.2.3.4 — known bad"],
            timeline=[{"_time": "2026-06-15T10:00:00Z"}],
            risk_score=0.85,
            recommendation="ESCALATE",
        )
        assert len(result.correlated_events) == 2
        assert len(result.ioc_matches) == 1
        assert result.risk_score == 0.85


class TestInvestigateAgent:
    """Tests for InvestigateAgent logic (without live MCP)."""

    def test_agent_initialization(self):
        agent = InvestigateAgent()
        assert agent.mcp is not None

    def test_build_timeline_sorting(self):
        agent = InvestigateAgent()
        alert = {"_time": "2026-06-15T10:30:00Z", "id": "main"}
        correlated = [
            {"_time": "2026-06-15T10:28:00Z", "id": "before"},
            {"_time": "2026-06-15T10:35:00Z", "id": "after"},
        ]
        timeline = agent._build_timeline(alert, correlated)
        assert timeline[0]["id"] == "before"
        assert timeline[1]["id"] == "main"
        assert timeline[2]["id"] == "after"

    def test_calculate_risk_base_severity(self):
        agent = InvestigateAgent()
        triage = TriageResult(severity=8, threshold=5, category="test", summary="", recommended_action="")
        risk = agent._calculate_risk(triage, [], [])
        assert risk == 0.8  # 8/10 base, no correlation or IOC bonus

    def test_calculate_risk_with_correlation(self):
        agent = InvestigateAgent()
        triage = TriageResult(severity=5, threshold=5, category="test", summary="", recommended_action="")
        correlated = [{"id": str(i)} for i in range(5)]
        risk = agent._calculate_risk(triage, correlated, [])
        # base=0.5, correlation_factor=min(5/10, 0.3)=0.3, ioc_factor=0
        assert risk == 0.5 + 0.3
        assert risk > 0.5

    def test_calculate_risk_capped_at_one(self):
        agent = InvestigateAgent()
        triage = TriageResult(severity=10, threshold=5, category="test", summary="", recommended_action="")
        correlated = [{"id": str(i)} for i in range(20)]
        iocs = ["ioc1", "ioc2", "ioc3", "ioc4", "ioc5"]
        risk = agent._calculate_risk(triage, correlated, iocs)
        assert risk <= 1.0

    def test_recommend_action_with_iocs(self):
        agent = InvestigateAgent()
        triage = TriageResult(severity=5, threshold=5, category="test", summary="", recommended_action="")
        recommendation = agent._recommend_action(triage, ["some_ioc"])
        assert "ESCALATE" in recommendation
        assert "IOC" in recommendation

    def test_recommend_action_high_severity(self):
        agent = InvestigateAgent()
        triage = TriageResult(severity=9, threshold=5, category="test", summary="", recommended_action="")
        recommendation = agent._recommend_action(triage, [])
        assert "ESCALATE" in recommendation

    def test_recommend_action_low_severity(self):
        agent = InvestigateAgent()
        triage = TriageResult(severity=3, threshold=5, category="test", summary="", recommended_action="")
        recommendation = agent._recommend_action(triage, [])
        assert "MONITOR" in recommendation
