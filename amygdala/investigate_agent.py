"""Sub-agent for correlation and investigation of triaged alerts."""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List

from .mcp_client import MCPClient, MCPConnectionError, MCPToolError
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
    """Correlates events and investigates alerts in depth.

    Spawns multiple sub-tasks concurrently to:
    - Search for correlated events by source IP
    - Check IOC feeds for known indicators
    - Build an event timeline
    - Calculate composite risk scores
    """

    def __init__(self):
        self.mcp = MCPClient()

    async def correlate(self, alert: dict, triage: TriageResult) -> InvestigationResult:
        """Investigate an alert by correlating related events.

        Runs correlation, IOC checks, and timeline building concurrently.

        Args:
            alert: The original alert dictionary
            triage: The triage evaluation result

        Returns:
            InvestigationResult with correlated data and recommendations
        """
        logger.info(f"Investigating alert: {alert.get('id')}")

        source_ip = alert.get("src_ip", "")
        dst_ip = alert.get("dst_ip", "")

        # Run sub-investigations concurrently
        correlated_task = self._search_correlated(source_ip)
        dst_correlated_task = self._search_correlated(dst_ip) if dst_ip else asyncio.coroutine(lambda: [])()
        ioc_task = self._check_iocs(alert)

        try:
            correlated, dst_events, iocs = await asyncio.gather(
                correlated_task,
                dst_correlated_task,
                ioc_task,
                return_exceptions=True,
            )
        except Exception as e:
            logger.error(f"Investigation sub-tasks failed: {e}")
            correlated, dst_events, iocs = [], [], []

        # Handle exceptions from gather
        if isinstance(correlated, Exception):
            logger.warning(f"Source IP correlation failed: {correlated}")
            correlated = []
        if isinstance(dst_events, Exception):
            logger.warning(f"Dest IP correlation failed: {dst_events}")
            dst_events = []
        if isinstance(iocs, Exception):
            logger.warning(f"IOC check failed: {iocs}")
            iocs = []

        # Merge and deduplicate correlated events
        all_correlated = self._deduplicate_events(correlated + dst_events)

        # Build timeline
        timeline = self._build_timeline(alert, all_correlated)

        # Calculate risk
        risk_score = self._calculate_risk(triage, all_correlated, iocs)

        # Generate recommendation
        recommendation = self._recommend_action(triage, iocs)

        result = InvestigationResult(
            correlated_events=all_correlated,
            ioc_matches=iocs,
            timeline=timeline,
            risk_score=risk_score,
            recommendation=recommendation,
        )

        logger.info(
            f"Investigation complete: {len(all_correlated)} correlated events, "
            f"{len(iocs)} IOCs, risk={risk_score:.2f}"
        )
        return result

    async def _search_correlated(self, source_ip: str) -> List[dict]:
        """Search for events correlated by source IP."""
        if not source_ip:
            return []

        try:
            result = await self.mcp.call_tool(
                tool_name="splunk_search",
                arguments={
                    "query": f'index=main src_ip="{source_ip}" | sort -_time | head 50',
                    "earliest_time": "-1h",
                    "latest_time": "now",
                },
            )
            return result.get("results", [])
        except (MCPConnectionError, MCPToolError) as e:
            logger.warning(f"Correlation search failed for {source_ip}: {e}")
            return []

    async def _check_iocs(self, alert: dict) -> List[str]:
        """Check alert indicators against IOC feeds.

        Extracts IPs, domains, and hashes from the alert and
        queries available threat intel feeds.
        """
        indicators = self._extract_indicators(alert)
        if not indicators:
            return []

        matches = []
        for indicator in indicators:
            try:
                result = await self.mcp.call_tool(
                    tool_name="threat_intel_lookup",
                    arguments={"indicator": indicator},
                )
                if result.get("found"):
                    matches.append(
                        f"{indicator} — {result.get('description', 'Match found')}"
                    )
            except (MCPConnectionError, MCPToolError):
                # IOC lookup is non-critical — continue without it
                logger.debug(f"IOC lookup unavailable for {indicator}")
                continue

        return matches

    def _extract_indicators(self, alert: dict) -> List[str]:
        """Extract potential IOC indicators from an alert."""
        indicators = []

        # IPs
        for field_name in ["src_ip", "dst_ip"]:
            ip = alert.get(field_name, "")
            if ip and not ip.startswith(("10.", "172.16.", "192.168.", "127.")):
                indicators.append(ip)

        # Hashes from raw data
        raw = alert.get("raw_data", {})
        if isinstance(raw, dict):
            for key in ["file_hash", "md5", "sha256", "sha1"]:
                if key in raw:
                    indicators.append(raw[key])

            # URLs/domains
            if "url" in raw:
                indicators.append(raw["url"])

        return indicators

    def _deduplicate_events(self, events: List[dict]) -> List[dict]:
        """Remove duplicate events based on _time and description."""
        seen = set()
        unique = []
        for event in events:
            key = (event.get("_time", ""), event.get("description", ""), event.get("src_ip", ""))
            if key not in seen:
                seen.add(key)
                unique.append(event)
        return unique

    def _build_timeline(self, alert: dict, correlated: List[dict]) -> List[dict]:
        """Build event timeline from alert and correlated events, sorted by time."""
        events = [alert] + correlated
        return sorted(events, key=lambda e: e.get("_time", e.get("timestamp", "")))

    def _calculate_risk(
        self, triage: TriageResult, correlated: List[dict], iocs: List[str]
    ) -> float:
        """Calculate composite risk score (0.0 to 1.0).

        Formula:
            risk = base_severity + correlation_bonus + ioc_bonus
            - base_severity: triage.severity / 10
            - correlation_bonus: min(num_correlated / 10, 0.3)
            - ioc_bonus: min(num_iocs * 0.1, 0.3)
        """
        base = triage.severity / 10.0
        correlation_factor = min(len(correlated) / 10.0, 0.3)
        ioc_factor = min(len(iocs) * 0.1, 0.3)
        return min(base + correlation_factor + ioc_factor, 1.0)

    def _recommend_action(self, triage: TriageResult, iocs: List[str]) -> str:
        """Generate action recommendation based on triage and IOCs."""
        if iocs:
            return "ESCALATE: IOC matches found - immediate response required"
        if triage.severity >= 8:
            return "ESCALATE: High severity - requires SOC analyst review"
        if triage.severity >= 5:
            return "INVESTIGATE: Moderate severity - gather additional context"
        return "MONITOR: Continue monitoring, no immediate action required"

    async def close(self):
        """Close the MCP client connection."""
        await self.mcp.close()
