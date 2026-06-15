"""Tests for demo mode — sample data loading, simulated triage, and investigation."""

import pytest

from amygdala.demo import (
    load_sample_alerts,
    simulate_triage,
    simulate_investigation,
    format_human_readable,
)
from amygdala.triage_agent import TriageResult
from amygdala.report_builder import ReportBuilder


class TestLoadSampleAlerts:
    """Tests for sample alert loading."""

    def test_loads_alerts(self):
        alerts = load_sample_alerts()
        assert len(alerts) == 5

    def test_alerts_have_required_fields(self):
        alerts = load_sample_alerts()
        for alert in alerts:
            assert "id" in alert
            assert "event_type" in alert
            assert "src_ip" in alert
            assert "description" in alert

    def test_alerts_have_unique_ids(self):
        alerts = load_sample_alerts()
        ids = [a["id"] for a in alerts]
        assert len(ids) == len(set(ids))

    def test_alert_event_types(self):
        alerts = load_sample_alerts()
        event_types = {a["event_type"] for a in alerts}
        expected = {"brute_force", "lateral_movement", "malware_download", "privilege_escalation", "port_scan"}
        assert event_types == expected


class TestSimulateTriage:
    """Tests for simulated triage evaluation."""

    def test_brute_force_triage(self):
        alert = {"event_type": "brute_force", "src_ip": "1.2.3.4"}
        result = simulate_triage(alert)
        assert isinstance(result, TriageResult)
        assert result.severity == 7
        assert result.category == "credential_attack"

    def test_lateral_movement_triage(self):
        alert = {"event_type": "lateral_movement", "src_ip": "1.2.3.4"}
        result = simulate_triage(alert)
        assert result.severity == 9
        assert result.category == "lateral_movement"

    def test_malware_triage(self):
        alert = {"event_type": "malware_download", "src_ip": "1.2.3.4"}
        result = simulate_triage(alert)
        assert result.severity == 9
        assert result.category == "malware"

    def test_privilege_escalation_triage(self):
        alert = {"event_type": "privilege_escalation", "src_ip": "1.2.3.4"}
        result = simulate_triage(alert)
        assert result.severity == 10
        assert result.category == "privilege_escalation"

    def test_port_scan_below_threshold(self):
        alert = {"event_type": "port_scan", "src_ip": "1.2.3.4"}
        result = simulate_triage(alert)
        assert result.severity == 4
        assert result.severity < result.threshold

    def test_unknown_event_type_fallback(self):
        alert = {"event_type": "unknown_thing", "src_ip": "1.2.3.4"}
        result = simulate_triage(alert)
        assert result.severity == 5
        assert result.category == "unknown"

    def test_triage_result_has_all_fields(self):
        alert = {"event_type": "brute_force", "src_ip": "1.2.3.4"}
        result = simulate_triage(alert)
        assert result.summary != ""
        assert result.recommended_action != ""
        assert result.threshold > 0


class TestSimulateInvestigation:
    """Tests for simulated investigation sub-agents."""

    def test_investigation_with_known_ip(self):
        alert = {"event_type": "brute_force", "src_ip": "192.168.1.100", "_time": "2026-06-15T10:30:00Z"}
        triage = simulate_triage(alert)
        result = simulate_investigation(alert, triage)
        assert len(result.correlated_events) > 0
        assert len(result.ioc_matches) > 0
        assert result.risk_score > 0

    def test_investigation_with_malware_ip(self):
        alert = {"event_type": "malware_download", "src_ip": "10.0.1.45", "dst_ip": "203.0.113.99", "_time": "2026-06-15T10:28:00Z"}
        triage = simulate_triage(alert)
        result = simulate_investigation(alert, triage)
        assert len(result.correlated_events) == 3
        assert len(result.ioc_matches) == 3
        assert "C2 server" in result.ioc_matches[0]

    def test_investigation_with_unknown_ip(self):
        alert = {"event_type": "brute_force", "src_ip": "99.99.99.99", "_time": "2026-06-15T10:30:00Z"}
        triage = simulate_triage(alert)
        result = simulate_investigation(alert, triage)
        assert result.correlated_events == []
        assert result.ioc_matches == []

    def test_risk_score_in_valid_range(self):
        alerts = load_sample_alerts()
        for alert in alerts:
            triage = simulate_triage(alert)
            result = simulate_investigation(alert, triage)
            assert 0.0 <= result.risk_score <= 1.0

    def test_timeline_includes_original_alert(self):
        alert = {"event_type": "brute_force", "src_ip": "192.168.1.100", "_time": "2026-06-15T10:30:00Z"}
        triage = simulate_triage(alert)
        result = simulate_investigation(alert, triage)
        assert alert in result.timeline

    def test_escalation_recommendation_with_iocs(self):
        alert = {"event_type": "malware_download", "src_ip": "10.0.1.45", "dst_ip": "203.0.113.99", "_time": "2026-06-15T10:28:00Z"}
        triage = simulate_triage(alert)
        result = simulate_investigation(alert, triage)
        assert "ESCALATE" in result.recommendation

    def test_monitor_recommendation_below_threshold(self):
        alert = {"event_type": "port_scan", "src_ip": "99.99.99.99", "_time": "2026-06-15T10:20:00Z"}
        triage = simulate_triage(alert)
        result = simulate_investigation(alert, triage)
        assert "MONITOR" in result.recommendation


class TestReportBuilder:
    """Tests for report generation."""

    def test_build_report_structure(self):
        alert = {"id": "TEST-001", "source": "splunk", "event_type": "brute_force", "src_ip": "192.168.1.100", "_time": "2026-06-15T10:30:00Z"}
        triage = simulate_triage(alert)
        investigation = simulate_investigation(alert, triage)
        builder = ReportBuilder()
        report = builder.build(alert, triage, investigation)

        assert "report_id" in report
        assert report["report_id"].startswith("INC-")
        assert "generated_at" in report
        assert "alert" in report
        assert "triage" in report
        assert "investigation" in report
        assert "status" in report

    def test_report_triage_section(self):
        alert = {"id": "TEST-001", "source": "splunk", "event_type": "malware_download", "src_ip": "10.0.1.45", "dst_ip": "203.0.113.99", "_time": "2026-06-15T10:28:00Z"}
        triage = simulate_triage(alert)
        investigation = simulate_investigation(alert, triage)
        builder = ReportBuilder()
        report = builder.build(alert, triage, investigation)

        assert report["triage"]["severity"] == 9
        assert report["triage"]["category"] == "malware"

    def test_report_investigation_section(self):
        alert = {"id": "TEST-001", "source": "splunk", "event_type": "brute_force", "src_ip": "192.168.1.100", "_time": "2026-06-15T10:30:00Z"}
        triage = simulate_triage(alert)
        investigation = simulate_investigation(alert, triage)
        builder = ReportBuilder()
        report = builder.build(alert, triage, investigation)

        assert report["investigation"]["correlated_events_count"] == 6
        assert report["investigation"]["risk_score"] > 0
        assert len(report["investigation"]["ioc_matches"]) > 0


class TestFormatHumanReadable:
    """Tests for human-readable report formatting."""

    def test_format_contains_report_id(self):
        alert = {"id": "TEST-001", "source": "splunk", "event_type": "brute_force", "src_ip": "192.168.1.100", "_time": "2026-06-15T10:30:00Z"}
        triage = simulate_triage(alert)
        investigation = simulate_investigation(alert, triage)
        builder = ReportBuilder()
        report = builder.build(alert, triage, investigation)
        output = format_human_readable(report)

        assert "INCIDENT REPORT" in output
        assert "INC-" in output

    def test_format_contains_severity_bar(self):
        alert = {"id": "TEST-001", "source": "splunk", "event_type": "privilege_escalation", "src_ip": "10.0.0.5", "_time": "2026-06-15T10:35:00Z"}
        triage = simulate_triage(alert)
        investigation = simulate_investigation(alert, triage)
        builder = ReportBuilder()
        report = builder.build(alert, triage, investigation)
        output = format_human_readable(report)

        assert "██████████" in output  # severity 10
        assert "10/10" in output

    def test_format_contains_iocs_section(self):
        alert = {"id": "TEST-001", "source": "splunk", "event_type": "malware_download", "src_ip": "10.0.1.45", "dst_ip": "203.0.113.99", "_time": "2026-06-15T10:28:00Z"}
        triage = simulate_triage(alert)
        investigation = simulate_investigation(alert, triage)
        builder = ReportBuilder()
        report = builder.build(alert, triage, investigation)
        output = format_human_readable(report)

        assert "IOC MATCHES" in output
        assert "VirusTotal" in output
