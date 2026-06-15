"""Structured incident report builder."""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from .triage_agent import TriageResult
from .investigate_agent import InvestigationResult

logger = logging.getLogger(__name__)


class ReportBuilder:
    """Builds structured incident reports from triage and investigation results.

    Generates two output formats:
    - Structured JSON for downstream automation and SIEM ingestion
    - Human-readable summary for Slack/analyst review
    """

    def build(
        self,
        alert: dict,
        triage: TriageResult,
        investigation: InvestigationResult,
    ) -> dict:
        """Build a structured incident report.

        Args:
            alert: Original alert dictionary
            triage: Triage evaluation result
            investigation: Investigation result with correlations

        Returns:
            Complete incident report as a dictionary
        """
        now = datetime.now(timezone.utc)
        report_id = f"INC-{now.strftime('%Y%m%d%H%M%S')}"

        report = {
            "report_id": report_id,
            "generated_at": now.isoformat(),
            "alert": {
                "id": alert.get("id"),
                "source": alert.get("source"),
                "timestamp": alert.get("_time", alert.get("timestamp")),
                "event_type": alert.get("event_type"),
                "src_ip": alert.get("src_ip"),
                "dst_ip": alert.get("dst_ip"),
                "host": alert.get("host"),
                "user": alert.get("user"),
                "description": alert.get("description"),
                "raw": alert,
            },
            "triage": {
                "severity": triage.severity,
                "category": triage.category,
                "summary": triage.summary,
                "recommended_action": triage.recommended_action,
            },
            "investigation": {
                "correlated_events_count": len(investigation.correlated_events),
                "ioc_matches": investigation.ioc_matches,
                "risk_score": investigation.risk_score,
                "recommendation": investigation.recommendation,
                "timeline_events": len(investigation.timeline),
            },
            "status": self._determine_status(triage, investigation),
            "assigned_to": None,
            "escalated": "ESCALATE" in investigation.recommendation,
        }

        logger.debug(f"Built report {report_id}: severity={triage.severity}, risk={investigation.risk_score:.2f}")
        return report

    def build_summary(
        self,
        alert: dict,
        triage: TriageResult,
        investigation: InvestigationResult,
    ) -> str:
        """Build a human-readable incident summary.

        Args:
            alert: Original alert dictionary
            triage: Triage evaluation result
            investigation: Investigation result

        Returns:
            Formatted multi-line string summary
        """
        severity_bar = "█" * triage.severity + "░" * (10 - triage.severity)
        risk_pct = int(investigation.risk_score * 100)

        lines = [
            f"━━━ INCIDENT: {alert.get('id', 'unknown')} ━━━",
            f"Severity: [{severity_bar}] {triage.severity}/10 | Risk: {risk_pct}%",
            f"Category: {triage.category}",
            f"Source: {alert.get('src_ip', 'N/A')} → {alert.get('dst_ip', 'N/A')}",
            f"",
            f"Summary: {triage.summary}",
            f"",
            f"Investigation: {len(investigation.correlated_events)} correlated events, "
            f"{len(investigation.ioc_matches)} IOC matches",
            f"Recommendation: {investigation.recommendation}",
        ]

        if investigation.ioc_matches:
            lines.append("")
            lines.append("IOC Matches:")
            for ioc in investigation.ioc_matches:
                lines.append(f"  • {ioc}")

        return "\n".join(lines)

    def _determine_status(self, triage: TriageResult, investigation: InvestigationResult) -> str:
        """Determine initial report status based on findings."""
        if "ESCALATE" in investigation.recommendation:
            return "escalated"
        if triage.severity >= 5:
            return "open"
        return "informational"
