"""Structured incident report builder."""

import logging
from datetime import datetime, timezone
from typing import Any

from .triage_agent import TriageResult
from .investigate_agent import InvestigationResult

logger = logging.getLogger(__name__)


class ReportBuilder:
    """Builds structured incident reports from triage and investigation results."""

    def build(
        self,
        alert: dict,
        triage: TriageResult,
        investigation: InvestigationResult,
    ) -> dict:
        """Build a structured incident report."""
        return {
            "report_id": f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "alert": {
                "id": alert.get("id"),
                "source": alert.get("source"),
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
            "status": "open",
            "assigned_to": None,
        }
