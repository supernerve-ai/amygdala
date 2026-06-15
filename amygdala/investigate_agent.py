"""Sub-agent for correlation and investigation of triaged alerts."""

import logging
from dataclasses import dataclass, field
from typing import List

from .mcp_client import MCPClient
from .triage_agent import TriageResult

logger = logging.getLogger(__name__)


@dataclass
class InvestigationResult:
    """Result of alert investigation."""
    correlated_events: List[dict] = field(default_factory=list)
    ioc_matches: List[str] = field(default_factory=list)
    timeline: List[dict] = field(default_factory=list)
    risk_score: float = 0.0
    recommendation: str = ""


class InvestigateAgent:
    """Correlates events and investigates alerts in depth."""

    def __init__(self):
        self.mcp = MCPClient()

    async def correlate(self, alert: dict, triage: TriageResult) -> InvestigationResult:
        """Investigate an alert by correlating related events."""
        logger.info(f"Investigating alert: {alert.get('id')}")

        # Search for correlated events
        source_ip = alert.get("src_ip", "")
        correlated = await self._search_correlated(source_ip)

        # Check IOC feeds
        iocs = await self._check_iocs(alert)

        # Build timeline
        timeline = self._build_timeline(alert, correlated)

        return InvestigationResult(
            correlated_events=correlated,
            ioc_matches=iocs,
            timeline=timeline,
            risk_score=self._calculate_risk(triage, correlated, iocs),
            recommendation=self._recommend_action(triage, iocs),
        )

    async def _search_correlated(self, source_ip: str) -> List[dict]:
        """Search for events correlated by source IP."""
        if not source_ip:
            return []

        result = await self.mcp.call_tool(
            tool_name="splunk_search",
            arguments={
                "query": f'index=main src_ip="{source_ip}" | head 50',
                "earliest_time": "-1h",
                "latest_time": "now",
            },
        )
        return result.get("results", [])

    async def _check_iocs(self, alert: dict) -> List[str]:
        """Check alert indicators against IOC feeds."""
        # Placeholder for IOC lookup integration
        return []

    def _build_timeline(self, alert: dict, correlated: List[dict]) -> List[dict]:
        """Build event timeline from alert and correlated events."""
        events = [alert] + correlated
        return sorted(events, key=lambda e: e.get("_time", ""))

    def _calculate_risk(
        self, triage: TriageResult, correlated: List[dict], iocs: List[str]
    ) -> float:
        """Calculate overall risk score."""
        base = triage.severity / 10.0
        correlation_factor = min(len(correlated) / 10.0, 0.3)
        ioc_factor = min(len(iocs) * 0.1, 0.3)
        return min(base + correlation_factor + ioc_factor, 1.0)

    def _recommend_action(self, triage: TriageResult, iocs: List[str]) -> str:
        """Generate action recommendation."""
        if iocs:
            return "ESCALATE: IOC matches found - immediate response required"
        if triage.severity >= 8:
            return "ESCALATE: High severity - requires SOC analyst review"
        return "MONITOR: Continue monitoring, no immediate action required"
