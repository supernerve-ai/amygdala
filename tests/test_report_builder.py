"""Tests for the report builder."""

import pytest
from datetime import datetime

from amygdala.report_builder import ReportBuilder
from amygdala.triage_agent import TriageResult
from amygdala.investigate_agent import InvestigationResult


class TestReportBuilder:
    """Tests for ReportBuilder."""

    def setup_method(self):
        self.builder = ReportBuilder()
        self.alert = {
            "id": "TEST-001",
            "source": "splunk",
            "event_type": "brute_force",
            "src_ip": "10.0.0.1",
        }
        self.triage = TriageResult(
            severity=7,
            threshold=5,
            category="credential_attack",
            summary="Brute force detected",
            recommended_action="Block IP",
        )
        self.investigation = InvestigationResult(
            correlated_events=[{"id": "1"}, {"id": "2"}, {"id": "3"}],
            ioc_matches=["10.0.0.1 — known attacker"],
            timeline=[{"_time": "t1"}, {"_time": "t2"}, {"_time": "t3"}, {"_time": "t4"}],
            risk_score=0.85,
            recommendation="ESCALATE: IOC match",
        )

    def test_report_has_id(self):
        report = self.builder.build(self.alert, self.triage, self.investigation)
        assert report["report_id"].startswith("INC-")

    def test_report_has_timestamp(self):
        report = self.builder.build(self.alert, self.triage, self.investigation)
        # Should be a valid ISO format timestamp
        assert "T" in report["generated_at"]

    def test_report_alert_section(self):
        report = self.builder.build(self.alert, self.triage, self.investigation)
        assert report["alert"]["id"] == "TEST-001"
        assert report["alert"]["source"] == "splunk"
        assert report["alert"]["raw"] == self.alert

    def test_report_triage_section(self):
        report = self.builder.build(self.alert, self.triage, self.investigation)
        assert report["triage"]["severity"] == 7
        assert report["triage"]["category"] == "credential_attack"
        assert report["triage"]["summary"] == "Brute force detected"
        assert report["triage"]["recommended_action"] == "Block IP"

    def test_report_investigation_section(self):
        report = self.builder.build(self.alert, self.triage, self.investigation)
        assert report["investigation"]["correlated_events_count"] == 3
        assert report["investigation"]["ioc_matches"] == ["10.0.0.1 — known attacker"]
        assert report["investigation"]["risk_score"] == 0.85
        assert report["investigation"]["recommendation"] == "ESCALATE: IOC match"
        assert report["investigation"]["timeline_events"] == 4

    def test_report_status_defaults_to_open(self):
        report = self.builder.build(self.alert, self.triage, self.investigation)
        # Investigation has "ESCALATE: IOC match" recommendation, so status is escalated
        assert report["status"] == "escalated"

    def test_report_status_open_when_no_escalation(self):
        investigation = InvestigationResult(
            correlated_events=[],
            ioc_matches=[],
            timeline=[],
            risk_score=0.5,
            recommendation="INVESTIGATE: needs more context",
        )
        triage = TriageResult(severity=6, threshold=5, category="test", summary="", recommended_action="")
        report = self.builder.build(self.alert, triage, investigation)
        assert report["status"] == "open"

    def test_report_unassigned_by_default(self):
        report = self.builder.build(self.alert, self.triage, self.investigation)
        assert report["assigned_to"] is None

    def test_report_with_empty_investigation(self):
        empty_investigation = InvestigationResult()
        report = self.builder.build(self.alert, self.triage, empty_investigation)
        assert report["investigation"]["correlated_events_count"] == 0
        assert report["investigation"]["ioc_matches"] == []
        assert report["investigation"]["risk_score"] == 0.0
        assert report["investigation"]["timeline_events"] == 0
