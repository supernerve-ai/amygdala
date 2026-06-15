"""SPL query and alert ingestion from Splunk via MCP."""

import os
import logging
from typing import List, Optional

from .mcp_client import MCPClient, MCPConnectionError, MCPToolError

logger = logging.getLogger(__name__)

DEFAULT_SPL_QUERY = 'index={index} sourcetype=alert earliest=-15m latest=now | head 100'

# SPL queries for different alert types
SPL_QUERIES = {
    "all_alerts": 'index={index} sourcetype=alert | head 100',
    "high_severity": 'index={index} sourcetype=alert severity>=high | head 50',
    "auth_failures": 'index={index} sourcetype=auth action=failure | stats count by src_ip, user | where count > 10',
    "network_anomalies": 'index={index} sourcetype=firewall action=blocked | stats count by src_ip | where count > 100',
    "malware_alerts": 'index={index} sourcetype=alert category=malware | head 50',
}


class AlertIngestor:
    """Ingests security alerts from Splunk using SPL queries via MCP.

    Handles query construction, result normalization, and error recovery.
    """

    def __init__(self):
        self.mcp = MCPClient()
        self.index = os.getenv("SPLUNK_INDEX", "main")
        self.earliest_time = os.getenv("SPLUNK_EARLIEST", "-15m")
        self.latest_time = os.getenv("SPLUNK_LATEST", "now")

    async def fetch_alerts(
        self,
        spl_query: Optional[str] = None,
        query_type: str = "all_alerts",
    ) -> List[dict]:
        """Fetch alerts from Splunk via MCP tool call.

        Args:
            spl_query: Custom SPL query string. If None, uses query_type.
            query_type: Predefined query key from SPL_QUERIES.

        Returns:
            List of alert dictionaries, normalized with standard fields.

        Raises:
            MCPConnectionError: If MCP server is unreachable.
        """
        if spl_query is None:
            template = SPL_QUERIES.get(query_type, SPL_QUERIES["all_alerts"])
            spl_query = template.format(index=self.index)

        logger.info(f"Running SPL query: {spl_query}")

        try:
            result = await self.mcp.call_tool(
                tool_name="splunk_search",
                arguments={
                    "query": spl_query,
                    "earliest_time": self.earliest_time,
                    "latest_time": self.latest_time,
                },
            )
        except MCPConnectionError as e:
            logger.error(f"Cannot reach Splunk via MCP: {e}")
            raise
        except MCPToolError as e:
            logger.error(f"SPL query failed: {e}")
            return []

        alerts = result.get("results", [])
        normalized = [self._normalize_alert(a) for a in alerts]
        logger.info(f"Ingested {len(normalized)} alerts from Splunk")
        return normalized

    async def fetch_correlated_events(
        self, source_ip: str, timeframe: str = "-1h"
    ) -> List[dict]:
        """Fetch events correlated by source IP.

        Args:
            source_ip: IP address to search for
            timeframe: Splunk relative time (e.g., '-1h', '-30m')

        Returns:
            List of correlated event dictionaries
        """
        if not source_ip:
            return []

        query = f'index={self.index} src_ip="{source_ip}" | sort -_time | head 50'
        logger.debug(f"Fetching correlated events for {source_ip}")

        try:
            result = await self.mcp.call_tool(
                tool_name="splunk_search",
                arguments={
                    "query": query,
                    "earliest_time": timeframe,
                    "latest_time": "now",
                },
            )
            return result.get("results", [])
        except (MCPConnectionError, MCPToolError) as e:
            logger.warning(f"Correlation search failed for {source_ip}: {e}")
            return []

    def _normalize_alert(self, raw: dict) -> dict:
        """Normalize a raw Splunk alert into a standard schema.

        Ensures all alerts have consistent field names regardless
        of the Splunk sourcetype or field extraction config.
        """
        return {
            "id": raw.get("id", raw.get("event_id", raw.get("_cd", "unknown"))),
            "source": raw.get("source", raw.get("sourcetype", "splunk")),
            "_time": raw.get("_time", raw.get("timestamp", "")),
            "event_type": raw.get("event_type", raw.get("category", raw.get("alert_type", "unknown"))),
            "src_ip": raw.get("src_ip", raw.get("src", raw.get("source_ip", ""))),
            "dst_ip": raw.get("dst_ip", raw.get("dst", raw.get("dest_ip", ""))),
            "src_port": raw.get("src_port", raw.get("source_port", 0)),
            "dst_port": raw.get("dst_port", raw.get("dest_port", 0)),
            "description": raw.get("description", raw.get("message", raw.get("alert_description", ""))),
            "user": raw.get("user", raw.get("username", raw.get("account", ""))),
            "host": raw.get("host", raw.get("hostname", raw.get("dest_host", ""))),
            "severity_hint": raw.get("severity_hint", raw.get("severity", raw.get("urgency", "medium"))),
            "count": raw.get("count", 1),
            "raw_data": raw,
        }

    async def close(self):
        """Close the MCP client connection."""
        await self.mcp.close()
